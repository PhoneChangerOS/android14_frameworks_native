/*
 * Copyright (C) 2019 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "ServiceManager.h"

#include <android-base/logging.h>
#include <android-base/properties.h>
#include <android-base/strings.h>
#include <binder/BpBinder.h>
#include <binder/IPCThreadState.h>
#include <binder/ProcessState.h>
#include <binder/Stability.h>
#include <cutils/android_filesystem_config.h>
#include <cutils/multiuser.h>
#include <thread>

#ifndef VENDORSERVICEMANAGER
#include <vintf/VintfObject.h>
#ifdef __ANDROID_RECOVERY__
#include <vintf/VintfObjectRecovery.h>
#endif // __ANDROID_RECOVERY__
#include <vintf/constants.h>
#endif  // !VENDORSERVICEMANAGER

#include "NameUtil.h"

using ::android::binder::Status;
using ::android::internal::Stability;

namespace android {

bool is_multiuser_uid_isolated(uid_t uid) {
    uid_t appid = multiuser_get_app_id(uid);
    return appid >= AID_ISOLATED_START && appid <= AID_ISOLATED_END;
}

#ifndef VENDORSERVICEMANAGER

struct ManifestWithDescription {
    std::shared_ptr<const vintf::HalManifest> manifest;
    const char* description;
};
static std::vector<ManifestWithDescription> GetManifestsWithDescription() {
#ifdef __ANDROID_RECOVERY__
    auto vintfObject = vintf::VintfObjectRecovery::GetInstance();
    if (vintfObject == nullptr) {
        ALOGE("NULL VintfObjectRecovery!");
        return {};
    }
    return {ManifestWithDescription{vintfObject->getRecoveryHalManifest(), "recovery"}};
#else
    auto vintfObject = vintf::VintfObject::GetInstance();
    if (vintfObject == nullptr) {
        ALOGE("NULL VintfObject!");
        return {};
    }
    return {ManifestWithDescription{vintfObject->getDeviceHalManifest(), "device"},
            ManifestWithDescription{vintfObject->getFrameworkHalManifest(), "framework"}};
#endif
}

// func true -> stop search and forEachManifest will return true
static bool forEachManifest(const std::function<bool(const ManifestWithDescription&)>& func) {
    for (const ManifestWithDescription& mwd : GetManifestsWithDescription()) {
        if (mwd.manifest == nullptr) {
            ALOGE("NULL VINTF MANIFEST!: %s", mwd.description);
            // note, we explicitly do not retry here, so that we can detect VINTF
            // or other bugs (b/151696835)
            continue;
        }
        if (func(mwd)) return true;
    }
    return false;
}

static std::string getNativeInstanceName(const vintf::ManifestInstance& instance) {
    return instance.package() + "/" + instance.instance();
}

struct AidlName {
    std::string package;
    std::string iface;
    std::string instance;

    static bool fill(const std::string& name, AidlName* aname) {
        size_t firstSlash = name.find('/');
        size_t lastDot = name.rfind('.', firstSlash);
        if (firstSlash == std::string::npos || lastDot == std::string::npos) {
            ALOGE("VINTF HALs require names in the format type/instance (e.g. "
                  "some.package.foo.IFoo/default) but got: %s",
                  name.c_str());
            return false;
        }
        aname->package = name.substr(0, lastDot);
        aname->iface = name.substr(lastDot + 1, firstSlash - lastDot - 1);
        aname->instance = name.substr(firstSlash + 1);
        return true;
    }
};

static std::string getAidlInstanceName(const vintf::ManifestInstance& instance) {
    return instance.package() + "." + instance.interface() + "/" + instance.instance();
}

static bool isVintfDeclared(const std::string& name) {
    NativeName nname;
    if (NativeName::fill(name, &nname)) {
        bool found = forEachManifest([&](const ManifestWithDescription& mwd) {
            if (mwd.manifest->hasNativeInstance(nname.package, nname.instance)) {
                ALOGI("Found %s in %s VINTF manifest.", name.c_str(), mwd.description);
                return true; // break
            }
            return false; // continue
        });
        if (!found) {
            ALOGI("Could not find %s in the VINTF manifest.", name.c_str());
        }
        return found;
    }

    AidlName aname;
    if (!AidlName::fill(name, &aname)) return false;

    bool found = forEachManifest([&](const ManifestWithDescription& mwd) {
        if (mwd.manifest->hasAidlInstance(aname.package, aname.iface, aname.instance)) {
            ALOGI("Found %s in %s VINTF manifest.", name.c_str(), mwd.description);
            return true; // break
        }
        return false;  // continue
    });

    if (!found) {
        std::set<std::string> instances;
        forEachManifest([&](const ManifestWithDescription& mwd) {
            std::set<std::string> res = mwd.manifest->getAidlInstances(aname.package, aname.iface);
            instances.insert(res.begin(), res.end());
            return true;
        });

        std::string available;
        if (instances.empty()) {
            available = "No alternative instances declared in VINTF";
        } else {
            // for logging only. We can't return this information to the client
            // because they may not have permissions to find or list those
            // instances
            available = "VINTF declared instances: " + base::Join(instances, ", ");
        }
        // Although it is tested, explicitly rebuilding qualified name, in case it
        // becomes something unexpected.
        ALOGI("Could not find %s.%s/%s in the VINTF manifest. %s.", aname.package.c_str(),
              aname.iface.c_str(), aname.instance.c_str(), available.c_str());
    }

    return found;
}

static std::optional<std::string> getVintfUpdatableApex(const std::string& name) {
    NativeName nname;
    if (NativeName::fill(name, &nname)) {
        std::optional<std::string> updatableViaApex;

        forEachManifest([&](const ManifestWithDescription& mwd) {
            bool cont = mwd.manifest->forEachInstance([&](const auto& manifestInstance) {
                if (manifestInstance.format() != vintf::HalFormat::NATIVE) return true;
                if (manifestInstance.package() != nname.package) return true;
                if (manifestInstance.instance() != nname.instance) return true;
                updatableViaApex = manifestInstance.updatableViaApex();
                return false; // break (libvintf uses opposite convention)
            });
            return !cont;
        });

        return updatableViaApex;
    }

    AidlName aname;
    if (!AidlName::fill(name, &aname)) return std::nullopt;

    std::optional<std::string> updatableViaApex;

    forEachManifest([&](const ManifestWithDescription& mwd) {
        bool cont = mwd.manifest->forEachInstance([&](const auto& manifestInstance) {
            if (manifestInstance.format() != vintf::HalFormat::AIDL) return true;
            if (manifestInstance.package() != aname.package) return true;
            if (manifestInstance.interface() != aname.iface) return true;
            if (manifestInstance.instance() != aname.instance) return true;
            updatableViaApex = manifestInstance.updatableViaApex();
            return false; // break (libvintf uses opposite convention)
        });
        return !cont;
    });

    return updatableViaApex;
}

static std::vector<std::string> getVintfUpdatableNames(const std::string& apexName) {
    std::vector<std::string> names;

    forEachManifest([&](const ManifestWithDescription& mwd) {
        mwd.manifest->forEachInstance([&](const auto& manifestInstance) {
            if (manifestInstance.updatableViaApex().has_value() &&
                manifestInstance.updatableViaApex().value() == apexName) {
                if (manifestInstance.format() == vintf::HalFormat::NATIVE) {
                    names.push_back(getNativeInstanceName(manifestInstance));
                } else if (manifestInstance.format() == vintf::HalFormat::AIDL) {
                    names.push_back(getAidlInstanceName(manifestInstance));
                }
            }
            return true; // continue (libvintf uses opposite convention)
        });
        return false; // continue
    });

    return names;
}

static std::optional<ConnectionInfo> getVintfConnectionInfo(const std::string& name) {
    AidlName aname;
    if (!AidlName::fill(name, &aname)) return std::nullopt;

    std::optional<std::string> ip;
    std::optional<uint64_t> port;
    forEachManifest([&](const ManifestWithDescription& mwd) {
        mwd.manifest->forEachInstance([&](const auto& manifestInstance) {
            if (manifestInstance.format() != vintf::HalFormat::AIDL) return true;
            if (manifestInstance.package() != aname.package) return true;
            if (manifestInstance.interface() != aname.iface) return true;
            if (manifestInstance.instance() != aname.instance) return true;
            ip = manifestInstance.ip();
            port = manifestInstance.port();
            return false; // break (libvintf uses opposite convention)
        });
        return false; // continue
    });

    if (ip.has_value() && port.has_value()) {
        ConnectionInfo info;
        info.ipAddress = *ip;
        info.port = *port;
        return std::make_optional<ConnectionInfo>(info);
    } else {
        return std::nullopt;
    }
}

static std::vector<std::string> getVintfInstances(const std::string& interface) {
    size_t lastDot = interface.rfind('.');
    if (lastDot == std::string::npos) {
        // This might be a package for native instance.
        std::vector<std::string> ret;
        (void)forEachManifest([&](const ManifestWithDescription& mwd) {
            auto instances = mwd.manifest->getNativeInstances(interface);
            ret.insert(ret.end(), instances.begin(), instances.end());
            return false; // continue
        });
        // If found, return it without error log.
        if (!ret.empty()) {
            return ret;
        }

        ALOGE("VINTF interfaces require names in Java package format (e.g. some.package.foo.IFoo) "
              "but got: %s",
              interface.c_str());
        return {};
    }
    const std::string package = interface.substr(0, lastDot);
    const std::string iface = interface.substr(lastDot+1);

    std::vector<std::string> ret;
    (void)forEachManifest([&](const ManifestWithDescription& mwd) {
        auto instances = mwd.manifest->getAidlInstances(package, iface);
        ret.insert(ret.end(), instances.begin(), instances.end());
        return false;  // continue
    });

    return ret;
}

static bool meetsDeclarationRequirements(const sp<IBinder>& binder, const std::string& name) {
    if (!Stability::requiresVintfDeclaration(binder)) {
        return true;
    }

    return isVintfDeclared(name);
}
#endif  // !VENDORSERVICEMANAGER

ServiceManager::Service::~Service() {
    if (hasClients) {
        // only expected to happen on process death, we don't store the service
        // name this late (it's in the map that holds this service), but if it
        // is happening, we might want to change 'unlinkToDeath' to explicitly
        // clear this bit so that we can abort in other cases, where it would
        // mean inconsistent logic in servicemanager (unexpected and tested, but
        // the original lazy service impl here had that bug).
        LOG(WARNING) << "a service was removed when there are clients";
    }
}

ServiceManager::ServiceManager(std::unique_ptr<Access>&& access) : mAccess(std::move(access)) {
// TODO(b/151696835): reenable performance hack when we solve bug, since with
//     this hack and other fixes, it is unlikely we will see even an ephemeral
//     failure when the manifest parse fails. The goal is that the manifest will
//     be read incorrectly and cause the process trying to register a HAL to
//     fail. If this is in fact an early boot kernel contention issue, then we
//     will get no failure, and by its absence, be signalled to invest more
//     effort in re-adding this performance hack.
// #ifndef VENDORSERVICEMANAGER
//     // can process these at any times, don't want to delay first VINTF client
//     std::thread([] {
//         vintf::VintfObject::GetDeviceHalManifest();
//         vintf::VintfObject::GetFrameworkHalManifest();
//     }).detach();
// #endif  // !VENDORSERVICEMANAGER
}
ServiceManager::~ServiceManager() {
    // this should only happen in tests

    for (const auto& [name, callbacks] : mNameToRegistrationCallback) {
        CHECK(!callbacks.empty()) << name;
        for (const auto& callback : callbacks) {
            CHECK(callback != nullptr) << name;
        }
    }

    for (const auto& [name, service] : mNameToService) {
        CHECK(service.binder != nullptr) << name;
    }
}

Status ServiceManager::getService(const std::string& name, sp<IBinder>* outBinder) {
    *outBinder = tryGetService(name, true);
    // returns ok regardless of result for legacy reasons
    return Status::ok();
}

Status ServiceManager::checkService(const std::string& name, sp<IBinder>* outBinder) {
    *outBinder = tryGetService(name, false);
    // returns ok regardless of result for legacy reasons
    return Status::ok();
}

sp<IBinder> ServiceManager::tryGetService(const std::string& name, bool startIfNotFound) {
    auto ctx = mAccess->getCallingContext();

    sp<IBinder> out;
    Service* service = nullptr;
    if (auto it = mNameToService.find(name); it != mNameToService.end()) {
        service = &(it->second);

        if (!service->allowIsolated && is_multiuser_uid_isolated(ctx.uid)) {
            LOG(WARNING) << "Isolated app with UID " << ctx.uid << " requested '" << name
                         << "', but the service is not allowed for isolated apps.";
            return nullptr;
        }
        out = service->binder;
    }

    if (!mAccess->canFind(ctx, name)) {
        return nullptr;
    }

    if (!out && startIfNotFound) {
        tryStartService(ctx, name);
    }

    if (out) {
        // Force onClients to get sent, and then make sure the timerfd won't clear it
        // by setting guaranteeClient again. This logic could be simplified by using
        // a time-based guarantee. However, forcing onClients(true) to get sent
        // right here is always going to be important for processes serving multiple
        // lazy interfaces.
        service->guaranteeClient = true;
        CHECK(handleServiceClientCallback(2 /* sm + transaction */, name, false));
        service->guaranteeClient = true;
    }

    return out;
}

bool isValidServiceName(const std::string& name) {
    if (name.size() == 0) return false;
    if (name.size() > 127) return false;

    for (char c : name) {
        if (c == '_' || c == '-' || c == '.' || c == '/') continue;
        if (c >= 'a' && c <= 'z') continue;
        if (c >= 'A' && c <= 'Z') continue;
        if (c >= '0' && c <= '9') continue;
        return false;
    }

    return true;
}

Status ServiceManager::addService(const std::string& name, const sp<IBinder>& binder, bool allowIsolated, int32_t dumpPriority) {
    auto ctx = mAccess->getCallingContext();

    if (multiuser_get_app_id(ctx.uid) >= AID_APP) {
        return Status::fromExceptionCode(Status::EX_SECURITY, "App UIDs cannot add services.");
    }

    if (!mAccess->canAdd(ctx, name)) {
        return Status::fromExceptionCode(Status::EX_SECURITY, "SELinux denied.");
    }

    if (binder == nullptr) {
        return Status::fromExceptionCode(Status::EX_ILLEGAL_ARGUMENT, "Null binder.");
    }

    if (!isValidServiceName(name)) {
        ALOGE("Invalid service name: %s", name.c_str());
        return Status::fromExceptionCode(Status::EX_ILLEGAL_ARGUMENT, "Invalid service name.");
    }

#ifndef VENDORSERVICEMANAGER
    if (!meetsDeclarationRequirements(binder, name)) {
        // already logged
        return Status::fromExceptionCode(Status::EX_ILLEGAL_ARGUMENT, "VINTF declaration error.");
    }
#endif  // !VENDORSERVICEMANAGER

    if ((dumpPriority & DUMP_FLAG_PRIORITY_ALL) == 0) {
        ALOGW("Dump flag priority is not set when adding %s", name.c_str());
    }

    // implicitly unlinked when the binder is removed
    if (binder->remoteBinder() != nullptr &&
        binder->linkToDeath(sp<ServiceManager>::fromExisting(this)) != OK) {
        ALOGE("Could not linkToDeath when adding %s", name.c_str());
        return Status::fromExceptionCode(Status::EX_ILLEGAL_STATE, "Couldn't linkToDeath.");
    }

    auto it = mNameToService.find(name);
    bool prevClients = false;
    if (it != mNameToService.end()) {
        const Service& existing = it->second;
        prevClients = existing.hasClients;

        // We could do better than this because if the other service dies, it
        // may not have an entry here. However, this case is unlikely. We are
        // only trying to detect when two different services are accidentally installed.

        if (existing.ctx.uid != ctx.uid) {
            ALOGW("Service '%s' originally registered from UID %u but it is now being registered "
                  "from UID %u. Multiple instances installed?",
                  name.c_str(), existing.ctx.uid, ctx.uid);
        }

        if (existing.ctx.sid != ctx.sid) {
            ALOGW("Service '%s' originally registered from SID %s but it is now being registered "
                  "from SID %s. Multiple instances installed?",
                  name.c_str(), existing.ctx.sid.c_str(), ctx.sid.c_str());
        }

        ALOGI("Service '%s' originally registered from PID %d but it is being registered again "
              "from PID %d. Bad state? Late death notification? Multiple instances installed?",
              name.c_str(), existing.ctx.debugPid, ctx.debugPid);
    }

    // Overwrite the old service if it exists
    mNameToService[name] = Service{
            .binder = binder,
            .allowIsolated = allowIsolated,
            .dumpPriority = dumpPriority,
            .hasClients = prevClients, // see b/279898063, matters if existing callbacks
            .guaranteeClient = false,
            .ctx = ctx,
    };

    if (auto it = mNameToRegistrationCallback.find(name); it != mNameToRegistrationCallback.end()) {
        // If someone is currently waiting on the service, notify the service that
        // we're waiting and flush it to the service.
        mNameToService[name].guaranteeClient = true;
        CHECK(handleServiceClientCallback(2 /* sm + transaction */, name, false));
        mNameToService[name].guaranteeClient = true;

        for (const sp<IServiceCallback>& cb : it->second) {
            // permission checked in registerForNotifications
            cb->onRegistration(name, binder);
        }
    }

    return Status::ok();
}

// --- SPOOF SERVICE LIST DATA (per-brand fake service list; hides custom-ROM/leaks) ---
#include <sys/system_properties.h>
#include <algorithm>

// AOSP Common Services
static const char* const kAospServiceList[] = {
"accessibility", "account", "activity", "activity_task", "adb",
"alarm", "android.frameworks.stats.IStats/default", "android.hardware.light.ILights/default", "android.hardware.power.IPower/default", "android.security.apc",
"android.security.authorization", "android.security.compat", "android.security.identity", "android.security.legacykeystore", "android.security.maintenance",
"android.security.metrics", "android.service.gatekeeper.IGateKeeperService", "android.system.keystore2.IKeystoreService/default", "android.system.suspend.ISystemSuspend/default", "app_binding",
"app_hibernation", "app_integrity", "appops", "app_search", "appwidget",
"attestation_verification", "audio", "auth", "autofill", "backup",
"battery", "batteryproperties", "batterystats", "binder_calls_stats", "biometric",
"blob_store", "bluetooth_manager", "bugreport", "cacheinfo", "carrier_config",
"clipboard", "color_display", "companiondevice", "connectivity", "connectivity_native",
"connmetrics", "content", "country_detector", "cpuinfo", "crossprofileapps",
"dataloader_manager", "dbinfo", "device_config", "device_identifiers", "deviceidle",
"device_policy", "device_state", "devicestoragemonitor", "diskstats", "display",
"dnsresolver", "DockObserver", "domain_verification", "dreams", "drm.drmManager",
"dropbox", "dynamic_system", "emergency_affordance", "ethernet", "external_vibrator_service",
"file_integrity", "fingerprint", "font", "game", "gfxinfo",
"gpu", "graphicsstats", "hardware_properties", "imms", "incident",
"incidentcompanion", "incremental", "input", "inputflinger", "input_method",
"installd", "ions", "iphonesubinfo", "ipsec", "isms",
"isub", "jobscheduler", "launcherapps", "legacy_permission", "lights",
"locale", "location", "location_time_zone_manager", "lock_settings", "logcat",
"looper_stats", "manager", "mdns", "media.audio_flinger", "media.audio_policy",
"media.camera", "media.camera.proxy", "media_communication", "media.extractor", "media.metrics",
"media_metrics", "media.player", "media_projection", "media.resource_manager", "media_resource_monitor",
"media.resource_observer", "media_router", "media_session", "meminfo", "memtrack.proxy",
"midi", "mount", "nearby", "netd", "netd_listener",
"netpolicy", "netstats", "network_management", "network_score", "network_stack",
"network_time_update_service", "network_watchlist", "nfc", "notification", "oem_lock",
"otadexopt", "overlay", "package", "package_native", "pac_proxy",
"people", "performance_hint", "permission", "permission_checker", "permissionmgr",
"persistent_data_block", "phone", "pinner", "platform_compat", "platform_compat_native",
"power", "powerstats", "print", "processinfo", "procstats",
"reboot_readiness", "recovery", "resources", "restrictions", "role",
"rollback", "runtime", "safety_center", "scheduling_policy", "sdk_sandbox",
"search", "sec_key_att_app_id_provider", "secure_element", "sensor_privacy", "sensorservice",
"serial", "servicediscovery", "settings", "shortcut", "simphonebook",
"slice", "soundtrigger", "soundtrigger_middleware", "speech_recognition", "stats",
"statsbootstrap", "statscompanion", "statsmanager", "statusbar", "storaged",
"storaged_pri", "storagestats", "SurfaceFlinger", "SurfaceFlingerAIDL", "suspend_control",
"suspend_control_internal", "system_config", "system_server_dumper", "system_update", "telecom",
"telephony_ims", "telephony.registry", "testharness", "tethering", "textclassification",
"textservices", "texttospeech", "thermalservice", "time_detector", "time_zone_detector",
"tracing.proxy", "transparency", "trust", "uimode", "updatelock",
"uri_grants", "usagestats", "usb", "user", "vcn_management",
"vibrator_manager", "virtualdevice", "voiceinteraction", "vold", "vpn_management",
"wallpaper", "webviewupdate", "wifi", "wifinl80211", "wifip2p",
"wifiscanner", "window",   
};
static const size_t kAospServiceListSize = sizeof(kAospServiceList) / sizeof(kAospServiceList[0]);

// Samsung-specific Services
static const char* const kSamsungServiceList[] = {
"adservices_manager", "android.frameworks.cameraservice.service.ICameraService/default", "android.frameworks.location.altitude.IAltitudeService/default", "android.frameworks.sensorservice.ISensorManager/default", "android.frameworks.vibrator.IVibratorControlService/default",
"android.hardware.media.c2.IComponentStore/software", "android.hardware.vibrator.IVibrator/default", "android.security.samsungattestation", "android.security.samsungpqcoperation", "android.security.securekeygeneration",
"android.system.net.netd.INetd/default", "AODManagerService", "app_function", "application_policy", "app_prediction",
"artd", "asks", "background_install_control", "blockchain", "ChimeraManagerService",
"CocktailBarService", "com.samsung.android.vexfwk.service", "com.samsung.security.fabric.cryptod.IFabricCryptoService/default", "com.samsung.ucs.ucsservice", "content_capture",
"contextual_search", "cover", "credential", "CustomFrequencyManagerService", "desktopmode",
"display_aiqe", "DisplaySolution", "dual_app", "ecm_enhanced_confirmation", "econtroller",
"edmnativehelper", "edm_proxy", "enterprise_license_policy", "enterprise_policy", "epdgService",
"epic", "euicc_card_controller", "extendedethernetservice", "face", "feature_flags",
"gamemanager", "grammatical_inflection", "healthconnect", "HqmManagerService", "ImsBase",
"IntelligentBatterySaverService", "isemphonesubinfo", "isemtelephony", "knoxcustom", "knoxguard_service",
"knox.mtd", "knox_ucsm_policy", "knox_vpn_policy", "kumiho.decoder", "lazy_service",
"lifeguard", "mcps", "mdm.remotedesktop", "mDNIe", "media.aaudio",
"media.camera.worker", "mobile_payment", "mocca", "motion_recognition", "multicontrol",
"mum_container_policy", "on_device_intelligence", "ondevicepersonalization_system_service", "perfsdkservice", "persona",
"PkgPredictorService", "profilepolicy", "profiling_service", "remoteappmode", "remote_provisioning",
"restriction_policy", "samsungnfc", "samsung_telecom", "SatsService", "scontext",
"sdhms", "SEAMService", "secims", "sec_location", "secure_element_mpos",
"security_state", "semclipboard", "SemContextEngineService", "SemContinuityService", "SemHwrsService",
"SemInputDeviceManagerService", "semprivilege", "SemService", "sem_ssdid", "sem_wifi",
"sem_wifi_aware", "sem_wifi_p2p", "sensitive_content_protection_service", "sepunion", "speg_helper",
"spengestureservice", "spqr_service", "stdp_service", "SveService", "translation",
"urspservice", "VaultKeeperService", "vendor.samsung.frameworks.codecsolution.ISehCodecSolution/default", "vendor.samsung.frameworks.hdrsolution.ISehHdrSolution/default", "vendor.samsung.frameworks.security.dsms.ISehDsms/default",
"vendor.samsung.hardware.hyper.ISehHyPer/default", "vendor.samsung.hardware.media.mpp.ISehMppStore/default", "vendor.samsung.hardware.security.fkeymaster.ISehFkeymaster/default", "vendor.samsung.hardware.security.hdcp.wifidisplay.ISehHdcp/default", "vendor.samsung.hardware.snap.ISehSnap/default",
"vendor.samsung.hardware.snap.ISehSnap/secsnap", "vendor.samsung.hardware.tlc.kg.ISehKg/default", "virtualdevice_native", "wearable_sensing", "wifiaware",
"wifirtt",    
};
static const size_t kSamsungServiceListSize = sizeof(kSamsungServiceList) / sizeof(kSamsungServiceList[0]);

// Xiaomi/Redmi/Poco-specific Services
static const char* const kXiaomiServiceList[] = {
"ambient_context", "android.hardware.gnss.IGnss/default", "android.hardware.identity.IIdentityCredentialStore/default", "android.hardware.memtrack.IMemtrack/default", "android.hardware.security.keymint.IKeyMintDevice/default",
"android.hardware.security.keymint.IRemotelyProvisionedComponent/default", "android.hardware.security.secureclock.ISecureClock/default", "android.hardware.security.sharedsecret.ISharedSecret/default", "android.hardware.vibrator.IVibrator/vibratorfeature", "android.os.UpdateEngineService",
"android.os.UpdateEngineStableService", "android.security.remoteprovisioning", "camera_covered_service", "cloudsearch", "consumer_ir",
"dpmservice", "extphone", "greezer", "migameshow", "migard",
"mi_nfc", "misight", "MiuiBackup", "miuiboosterservice", "MiuiCarService",
"miui.cld.service", "miui.contentcatcher.ContentCatcherService", "miui.dfc.service", "miui.face.FaceService", "miui.fbo.service",
"miui.fdpp", "MiuiFreeDragService", "MiuiInit", "MiuiInputManager", "miui.memory.service",
"miui.mirror_app_service", "miui.mirror_service", "miui.mqsas.IMQSNative", "miui.radio.extphone", "miui.restore.service",
"miui.sedc", "miui.shell", "miui_step_counter_service", "miuiwebview", "miui.whetstone.klo",
"miui.whetstone.mcd", "miui.whetstone.power", "MiuiWifiService", "perfshielder", "ProcessManager",
"qti.radio.extphone", "SchedBoostService", "search_ui", "security", "shoulderkey",
"SlaveWifiService", "smartpower", "smartspace", "tare", "turbosched",
"vendor.perfservice", "vendor.qspmsvc", "vendor.qti.gnss.ILocAidlGnss/default", "vendor.qti.hardware.data.connectionfactory.IFactory/slot0", "vendor.qti.hardware.data.connectionfactory.IFactory/slot1",
"vendor.qti.hardware.display.config.IDisplayConfig/default", "vendor.qti.hardware.qxr.IQXRAudioService/default", "vendor.qti.hardware.qxr.IQXRCamService/default", "vendor.qti.hardware.qxr.IQXRCoreService/default", "vendor.qti.hardware.qxr.IQXRModService/default",
"vendor.qti.hardware.qxr.IQXRSplitService/default", "vendor.qti.hardware.radio.ims.IImsRadio/imsradio0", "vendor.qti.hardware.radio.ims.IImsRadio/imsradio1", "vendor.qti.hardware.radio.qtiradio.IQtiRadioStable/slot1", "vendor.qti.hardware.radio.qtiradio.IQtiRadioStable/slot2",
"wallpaper_effects_generation", "whetstone.activity", "xiaomi.joyose",  
};
static const size_t kXiaomiServiceListSize = sizeof(kXiaomiServiceList) / sizeof(kXiaomiServiceList[0]);


static std::vector<std::string> getFakeServices() {
    static std::vector<std::string> sFakeServices;
    if (!sFakeServices.empty()) return sFakeServices;
    char brand[PROP_VALUE_MAX];
    __system_property_get("ro.product.brand", brand);
    std::string b(brand);
    std::transform(b.begin(), b.end(), b.begin(), ::tolower);
    for (size_t i = 0; i < kAospServiceListSize; i++) sFakeServices.push_back(kAospServiceList[i]);
    if (b == "samsung") {
        for (size_t i = 0; i < kSamsungServiceListSize; i++) sFakeServices.push_back(kSamsungServiceList[i]);
    } else if (b == "xiaomi" || b == "redmi" || b == "poco") {
        for (size_t i = 0; i < kXiaomiServiceListSize; i++) sFakeServices.push_back(kXiaomiServiceList[i]);
    }
    ALOGI("Loaded %zu fake services for brand: %s", sFakeServices.size(), brand);
    return sFakeServices;
}
// --- END SPOOF DATA ---

Status ServiceManager::listServices(int32_t dumpPriority, std::vector<std::string>* outList) {
    if (!mAccess->canList(mAccess->getCallingContext())) {
        return Status::fromExceptionCode(Status::EX_SECURITY, "SELinux denied.");
    }

    // SPOOF START: replace real service list with per-brand fake list
    std::vector<std::string> fake = getFakeServices();
    if (!fake.empty()) {
        *outList = std::move(fake);
        return Status::ok();
    }
    // SPOOF END

    size_t toReserve = 0;
    for (auto const& [name, service] : mNameToService) {
        (void) name;

        if (service.dumpPriority & dumpPriority) ++toReserve;
    }

    CHECK(outList->empty());

    outList->reserve(toReserve);
    for (auto const& [name, service] : mNameToService) {
        (void) service;

        if (service.dumpPriority & dumpPriority) {
            outList->push_back(name);
        }
    }

    return Status::ok();
}

Status ServiceManager::registerForNotifications(
        const std::string& name, const sp<IServiceCallback>& callback) {
    auto ctx = mAccess->getCallingContext();

    if (!mAccess->canFind(ctx, name)) {
        return Status::fromExceptionCode(Status::EX_SECURITY, "SELinux");
    }

    // note - we could allow isolated apps to get notifications if we
    // keep track of isolated callbacks and non-isolated callbacks, but
    // this is done since isolated apps shouldn't access lazy services
    // so we should be able to use different APIs to keep things simple.
    // Here, we disallow everything, because the service might not be
    // registered yet.
    if (is_multiuser_uid_isolated(ctx.uid)) {
        return Status::fromExceptionCode(Status::EX_SECURITY, "isolated app");
    }

    if (!isValidServiceName(name)) {
        ALOGE("Invalid service name: %s", name.c_str());
        return Status::fromExceptionCode(Status::EX_ILLEGAL_ARGUMENT, "Invalid service name.");
    }

    if (callback == nullptr) {
        return Status::fromExceptionCode(Status::EX_NULL_POINTER, "Null callback.");
    }

    if (OK !=
        IInterface::asBinder(callback)->linkToDeath(
                sp<ServiceManager>::fromExisting(this))) {
        ALOGE("Could not linkToDeath when adding %s", name.c_str());
        return Status::fromExceptionCode(Status::EX_ILLEGAL_STATE, "Couldn't link to death.");
    }

    mNameToRegistrationCallback[name].push_back(callback);

    if (auto it = mNameToService.find(name); it != mNameToService.end()) {
        const sp<IBinder>& binder = it->second.binder;

        // never null if an entry exists
        CHECK(binder != nullptr) << name;
        callback->onRegistration(name, binder);
    }

    return Status::ok();
}
Status ServiceManager::unregisterForNotifications(
        const std::string& name, const sp<IServiceCallback>& callback) {
    auto ctx = mAccess->getCallingContext();

    if (!mAccess->canFind(ctx, name)) {
        return Status::fromExceptionCode(Status::EX_SECURITY, "SELinux denied.");
    }

    bool found = false;

    auto it = mNameToRegistrationCallback.find(name);
    if (it != mNameToRegistrationCallback.end()) {
        removeRegistrationCallback(IInterface::asBinder(callback), &it, &found);
    }

    if (!found) {
        ALOGE("Trying to unregister callback, but none exists %s", name.c_str());
        return Status::fromExceptionCode(Status::EX_ILLEGAL_STATE, "Nothing to unregister.");
    }

    return Status::ok();
}

Status ServiceManager::isDeclared(const std::string& name, bool* outReturn) {
    auto ctx = mAccess->getCallingContext();

    if (!mAccess->canFind(ctx, name)) {
        return Status::fromExceptionCode(Status::EX_SECURITY, "SELinux denied.");
    }

    *outReturn = false;

#ifndef VENDORSERVICEMANAGER
    *outReturn = isVintfDeclared(name);
#endif
    return Status::ok();
}

binder::Status ServiceManager::getDeclaredInstances(const std::string& interface, std::vector<std::string>* outReturn) {
    auto ctx = mAccess->getCallingContext();

    std::vector<std::string> allInstances;
#ifndef VENDORSERVICEMANAGER
    allInstances = getVintfInstances(interface);
#endif

    outReturn->clear();

    for (const std::string& instance : allInstances) {
        if (mAccess->canFind(ctx, interface + "/" + instance)) {
            outReturn->push_back(instance);
        }
    }

    if (outReturn->size() == 0 && allInstances.size() != 0) {
        return Status::fromExceptionCode(Status::EX_SECURITY, "SELinux denied.");
    }

    return Status::ok();
}

Status ServiceManager::updatableViaApex(const std::string& name,
                                        std::optional<std::string>* outReturn) {
    auto ctx = mAccess->getCallingContext();

    if (!mAccess->canFind(ctx, name)) {
        return Status::fromExceptionCode(Status::EX_SECURITY, "SELinux denied.");
    }

    *outReturn = std::nullopt;

#ifndef VENDORSERVICEMANAGER
    *outReturn = getVintfUpdatableApex(name);
#endif
    return Status::ok();
}

Status ServiceManager::getUpdatableNames([[maybe_unused]] const std::string& apexName,
                                         std::vector<std::string>* outReturn) {
    auto ctx = mAccess->getCallingContext();

    std::vector<std::string> apexUpdatableNames;
#ifndef VENDORSERVICEMANAGER
    apexUpdatableNames = getVintfUpdatableNames(apexName);
#endif

    outReturn->clear();

    for (const std::string& name : apexUpdatableNames) {
        if (mAccess->canFind(ctx, name)) {
            outReturn->push_back(name);
        }
    }

    if (outReturn->size() == 0 && apexUpdatableNames.size() != 0) {
        return Status::fromExceptionCode(Status::EX_SECURITY, "SELinux denied.");
    }

    return Status::ok();
}

Status ServiceManager::getConnectionInfo(const std::string& name,
                                         std::optional<ConnectionInfo>* outReturn) {
    auto ctx = mAccess->getCallingContext();

    if (!mAccess->canFind(ctx, name)) {
        return Status::fromExceptionCode(Status::EX_SECURITY, "SELinux denied.");
    }

    *outReturn = std::nullopt;

#ifndef VENDORSERVICEMANAGER
    *outReturn = getVintfConnectionInfo(name);
#endif
    return Status::ok();
}

void ServiceManager::removeRegistrationCallback(const wp<IBinder>& who,
                                    ServiceCallbackMap::iterator* it,
                                    bool* found) {
    std::vector<sp<IServiceCallback>>& listeners = (*it)->second;

    for (auto lit = listeners.begin(); lit != listeners.end();) {
        if (IInterface::asBinder(*lit) == who) {
            if(found) *found = true;
            lit = listeners.erase(lit);
        } else {
            ++lit;
        }
    }

    if (listeners.empty()) {
        *it = mNameToRegistrationCallback.erase(*it);
    } else {
        (*it)++;
    }
}

void ServiceManager::binderDied(const wp<IBinder>& who) {
    for (auto it = mNameToService.begin(); it != mNameToService.end();) {
        if (who == it->second.binder) {
            // TODO: currently, this entry contains the state also
            // associated with mNameToClientCallback. If we allowed
            // other processes to register client callbacks, we
            // would have to preserve hasClients (perhaps moving
            // that state into mNameToClientCallback, which is complicated
            // because those callbacks are associated w/ particular binder
            // objects, though they are indexed by name now, they may
            // need to be indexed by binder at that point).
            it = mNameToService.erase(it);
        } else {
            ++it;
        }
    }

    for (auto it = mNameToRegistrationCallback.begin(); it != mNameToRegistrationCallback.end();) {
        removeRegistrationCallback(who, &it, nullptr /*found*/);
    }

    for (auto it = mNameToClientCallback.begin(); it != mNameToClientCallback.end();) {
        removeClientCallback(who, &it);
    }
}

void ServiceManager::tryStartService(const Access::CallingContext& ctx, const std::string& name) {
    ALOGI("Since '%s' could not be found (requested by debug pid %d), trying to start it as a lazy "
          "AIDL service. (if it's not configured to be a lazy service, it may be stuck starting or "
          "still starting).",
          name.c_str(), ctx.debugPid);

    std::thread([=] {
        if (!base::SetProperty("ctl.interface_start", "aidl/" + name)) {
            ALOGI("Tried to start aidl service %s as a lazy service, but was unable to. Usually "
                  "this happens when a "
                  "service is not installed, but if the service is intended to be used as a "
                  "lazy service, then it may be configured incorrectly.",
                  name.c_str());
        }
    }).detach();
}

Status ServiceManager::registerClientCallback(const std::string& name, const sp<IBinder>& service,
                                              const sp<IClientCallback>& cb) {
    if (cb == nullptr) {
        return Status::fromExceptionCode(Status::EX_NULL_POINTER, "Callback null.");
    }

    auto ctx = mAccess->getCallingContext();
    if (!mAccess->canAdd(ctx, name)) {
        return Status::fromExceptionCode(Status::EX_SECURITY, "SELinux denied.");
    }

    auto serviceIt = mNameToService.find(name);
    if (serviceIt == mNameToService.end()) {
        ALOGE("Could not add callback for nonexistent service: %s", name.c_str());
        return Status::fromExceptionCode(Status::EX_ILLEGAL_ARGUMENT, "Service doesn't exist.");
    }

    if (serviceIt->second.ctx.debugPid != IPCThreadState::self()->getCallingPid()) {
        ALOGW("Only a server can register for client callbacks (for %s)", name.c_str());
        return Status::fromExceptionCode(Status::EX_UNSUPPORTED_OPERATION,
                                         "Only service can register client callback for itself.");
    }

    if (serviceIt->second.binder != service) {
        ALOGW("Tried to register client callback for %s but a different service is registered "
              "under this name.",
              name.c_str());
        return Status::fromExceptionCode(Status::EX_ILLEGAL_ARGUMENT, "Service mismatch.");
    }

    if (OK !=
        IInterface::asBinder(cb)->linkToDeath(sp<ServiceManager>::fromExisting(this))) {
        ALOGE("Could not linkToDeath when adding client callback for %s", name.c_str());
        return Status::fromExceptionCode(Status::EX_ILLEGAL_STATE, "Couldn't linkToDeath.");
    }

    // WARNING: binderDied makes an assumption about this. If we open up client
    // callbacks to other services, certain race conditions may lead to services
    // getting extra client callback notifications.
    // Make sure all callbacks have been told about a consistent state - b/278038751
    if (serviceIt->second.hasClients) {
        cb->onClients(service, true);
    }

    mNameToClientCallback[name].push_back(cb);

    // Flush updated info to client callbacks (especially if guaranteeClient
    // and !hasClient, see b/285202885). We may or may not have clients at
    // this point, so ignore the return value.
    (void)handleServiceClientCallback(2 /* sm + transaction */, name, false);

    return Status::ok();
}

void ServiceManager::removeClientCallback(const wp<IBinder>& who,
                                          ClientCallbackMap::iterator* it) {
    std::vector<sp<IClientCallback>>& listeners = (*it)->second;

    for (auto lit = listeners.begin(); lit != listeners.end();) {
        if (IInterface::asBinder(*lit) == who) {
            lit = listeners.erase(lit);
        } else {
            ++lit;
        }
    }

    if (listeners.empty()) {
        *it = mNameToClientCallback.erase(*it);
    } else {
        (*it)++;
    }
}

ssize_t ServiceManager::Service::getNodeStrongRefCount() {
    sp<BpBinder> bpBinder = sp<BpBinder>::fromExisting(binder->remoteBinder());
    if (bpBinder == nullptr) return -1;

    return ProcessState::self()->getStrongRefCountForNode(bpBinder);
}

void ServiceManager::handleClientCallbacks() {
    for (const auto& [name, service] : mNameToService) {
        handleServiceClientCallback(1 /* sm has one refcount */, name, true);
    }
}

bool ServiceManager::handleServiceClientCallback(size_t knownClients,
                                                 const std::string& serviceName,
                                                 bool isCalledOnInterval) {
    auto serviceIt = mNameToService.find(serviceName);
    if (serviceIt == mNameToService.end() || mNameToClientCallback.count(serviceName) < 1) {
        return true; // return we do have clients a.k.a. DON'T DO ANYTHING
    }

    Service& service = serviceIt->second;
    ssize_t count = service.getNodeStrongRefCount();

    // binder driver doesn't support this feature, consider we have clients
    if (count == -1) return true;

    bool hasKernelReportedClients = static_cast<size_t>(count) > knownClients;

    if (service.guaranteeClient) {
        if (!service.hasClients && !hasKernelReportedClients) {
            sendClientCallbackNotifications(serviceName, true,
                                            "service is guaranteed to be in use");
        }

        // guarantee is temporary
        service.guaranteeClient = false;
    }

    // Regardless of this situation, we want to give this notification as soon as possible.
    // This way, we have a chance of preventing further thrashing.
    if (hasKernelReportedClients && !service.hasClients) {
        sendClientCallbackNotifications(serviceName, true, "we now have a record of a client");
    }

    // But limit rate of shutting down service.
    if (isCalledOnInterval) {
        if (!hasKernelReportedClients && service.hasClients) {
            sendClientCallbackNotifications(serviceName, false,
                                            "we now have no record of a client");
        }
    }

    // May be different than 'hasKernelReportedClients'. We intentionally delay
    // information about clients going away to reduce thrashing.
    return service.hasClients;
}

void ServiceManager::sendClientCallbackNotifications(const std::string& serviceName,
                                                     bool hasClients, const char* context) {
    auto serviceIt = mNameToService.find(serviceName);
    if (serviceIt == mNameToService.end()) {
        ALOGW("sendClientCallbackNotifications could not find service %s when %s",
              serviceName.c_str(), context);
        return;
    }
    Service& service = serviceIt->second;

    CHECK_NE(hasClients, service.hasClients) << context;

    ALOGI("Notifying %s they %s (previously: %s) have clients when %s", serviceName.c_str(),
          hasClients ? "do" : "don't", service.hasClients ? "do" : "don't", context);

    auto ccIt = mNameToClientCallback.find(serviceName);
    CHECK(ccIt != mNameToClientCallback.end())
            << "sendClientCallbackNotifications could not find callbacks for service when "
            << context;

    for (const auto& callback : ccIt->second) {
        callback->onClients(service.binder, hasClients);
    }

    service.hasClients = hasClients;
}

Status ServiceManager::tryUnregisterService(const std::string& name, const sp<IBinder>& binder) {
    if (binder == nullptr) {
        return Status::fromExceptionCode(Status::EX_NULL_POINTER, "Null service.");
    }

    auto ctx = mAccess->getCallingContext();
    if (!mAccess->canAdd(ctx, name)) {
        return Status::fromExceptionCode(Status::EX_SECURITY, "SELinux denied.");
    }

    auto serviceIt = mNameToService.find(name);
    if (serviceIt == mNameToService.end()) {
        ALOGW("Tried to unregister %s, but that service wasn't registered to begin with.",
              name.c_str());
        return Status::fromExceptionCode(Status::EX_ILLEGAL_STATE, "Service not registered.");
    }

    if (serviceIt->second.ctx.debugPid != IPCThreadState::self()->getCallingPid()) {
        ALOGW("Only a server can unregister itself (for %s)", name.c_str());
        return Status::fromExceptionCode(Status::EX_UNSUPPORTED_OPERATION,
                                         "Service can only unregister itself.");
    }

    sp<IBinder> storedBinder = serviceIt->second.binder;

    if (binder != storedBinder) {
        ALOGW("Tried to unregister %s, but a different service is registered under this name.",
              name.c_str());
        return Status::fromExceptionCode(Status::EX_ILLEGAL_STATE,
                                         "Different service registered under this name.");
    }

    // important because we don't have timer-based guarantees, we don't want to clear
    // this
    if (serviceIt->second.guaranteeClient) {
        ALOGI("Tried to unregister %s, but there is about to be a client.", name.c_str());
        return Status::fromExceptionCode(Status::EX_ILLEGAL_STATE,
                                         "Can't unregister, pending client.");
    }

    // - kernel driver will hold onto one refcount (during this transaction)
    // - servicemanager has a refcount (guaranteed by this transaction)
    constexpr size_t kKnownClients = 2;

    if (handleServiceClientCallback(kKnownClients, name, false)) {
        ALOGI("Tried to unregister %s, but there are clients.", name.c_str());

        // Since we had a failed registration attempt, and the HIDL implementation of
        // delaying service shutdown for multiple periods wasn't ported here... this may
        // help reduce thrashing, but we should be able to remove it.
        serviceIt->second.guaranteeClient = true;

        return Status::fromExceptionCode(Status::EX_ILLEGAL_STATE,
                                         "Can't unregister, known client.");
    }

    ALOGI("Unregistering %s", name.c_str());
    mNameToService.erase(name);

    return Status::ok();
}

Status ServiceManager::getServiceDebugInfo(std::vector<ServiceDebugInfo>* outReturn) {
    if (!mAccess->canList(mAccess->getCallingContext())) {
        return Status::fromExceptionCode(Status::EX_SECURITY, "SELinux denied.");
    }

    outReturn->reserve(mNameToService.size());
    for (auto const& [name, service] : mNameToService) {
        ServiceDebugInfo info;
        info.name = name;
        info.debugPid = service.ctx.debugPid;

        outReturn->push_back(std::move(info));
    }

    return Status::ok();
}

void ServiceManager::clear() {
    mNameToService.clear();
    mNameToRegistrationCallback.clear();
    mNameToClientCallback.clear();
}

}  // namespace android
