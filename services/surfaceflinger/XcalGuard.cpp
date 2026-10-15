#include "XcalGuard.h"
#include "XcalLockImage.h"

#include <android-base/properties.h>
#include <gui/SurfaceComposerClient.h>
#include <gui/SurfaceControl.h>
#include <ui/DisplayMode.h>
#include <ui/GraphicBuffer.h>
#include <ui/LayerStack.h>
#include <ui/Rect.h>
#include <openssl/evp.h>

#include <time.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <ctime>
#include <string>
#include <thread>
#include <vector>

namespace android {
namespace {

constexpr uint8_t kM = 0x3C;
std::string dm(const uint8_t* b, size_t n) {
    std::string s;
    s.reserve(n);
    for (size_t i = 0; i < n; i++) s += static_cast<char>(b[i] ^ kM);
    return s;
}

std::string hwId() {
    std::string s = base::GetProperty("ro.product.sn", "");
    if (s.empty()) s = base::GetProperty("ro.serialno", "");
    return s;
}

std::string unwrap(const std::string& in, const std::string& k, const std::string& iv) {
    if (in.size() < 32 || (in.size() & 1)) return "";
    std::vector<uint8_t> raw;
    raw.reserve(in.size() / 2);
    for (size_t i = 0; i < in.size(); i += 2)
        raw.push_back(static_cast<uint8_t>(strtoul(in.substr(i, 2).c_str(), nullptr, 16)));
    unsigned char out[1024];
    int ol = 0, tl = 0;
    EVP_CIPHER_CTX* c = EVP_CIPHER_CTX_new();
    if (!c) return "";
    EVP_DecryptInit_ex(c, EVP_aes_128_cbc(), nullptr,
                       reinterpret_cast<const unsigned char*>(k.c_str()),
                       reinterpret_cast<const unsigned char*>(iv.c_str()));
    if (!EVP_DecryptUpdate(c, out, &ol, raw.data(), static_cast<int>(raw.size())) ||
        !EVP_DecryptFinal_ex(c, out + ol, &tl)) {
        EVP_CIPHER_CTX_free(c);
        return "";
    }
    ol += tl;
    EVP_CIPHER_CTX_free(c);
    return std::string(reinterpret_cast<char*>(out), static_cast<size_t>(ol));
}

const unsigned char kPub[32] = {
    0x9b, 0x1f, 0x29, 0x54, 0x68, 0xb2, 0x5f, 0x31, 0x48, 0xdf, 0xd6, 0xc1, 0x2c, 0xc2, 0xbf, 0xb4,
    0x25, 0x8d, 0x24, 0x43, 0x62, 0x8d, 0x20, 0xd1, 0x09, 0x25, 0xd7, 0x60, 0x69, 0x90, 0x21, 0xc1};

int b64d(const char* in, unsigned char* out, int omax) {
    int acc = 0, nb = 0, n = 0;
    for (const char* p = in; *p && *p != '='; p++) {
        int v;
        char c = *p;
        if (c >= 'A' && c <= 'Z') v = c - 'A';
        else if (c >= 'a' && c <= 'z') v = c - 'a' + 26;
        else if (c >= '0' && c <= '9') v = c - '0' + 52;
        else if (c == '+') v = 62;
        else if (c == '/') v = 63;
        else return -1;
        acc = (acc << 6) | v;
        nb += 6;
        if (nb >= 8) {
            nb -= 8;
            if (n >= omax) return -1;
            out[n++] = static_cast<unsigned char>((acc >> nb) & 0xff);
        }
    }
    return n;
}

bool sig_ok(const std::string& msg, const std::string& sb) {
    unsigned char sig[64];
    if (b64d(sb.c_str(), sig, 64) != 64) return false;
    EVP_PKEY* pk = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, nullptr, kPub, 32);
    if (!pk) return false;
    EVP_MD_CTX* c = EVP_MD_CTX_new();
    bool ok = c && EVP_DigestVerifyInit(c, nullptr, nullptr, nullptr, pk) == 1 &&
              EVP_DigestVerify(c, sig, 64, reinterpret_cast<const unsigned char*>(msg.data()),
                               msg.size()) == 1;
    if (c) EVP_MD_CTX_free(c);
    EVP_PKEY_free(pk);
    return ok;
}

// true = licensed (no lock). Mirrors the libandroid_servers watchdog decision; fail-open on the
// early-boot window so a device that has not yet fetched its token is never locked at boot.
bool licensed() {
    struct timespec ts;
    clock_gettime(CLOCK_BOOTTIME, &ts);
    if (ts.tv_sec < 360) return true;  // boot grace

    static const uint8_t p[] = {0x4C, 0x59, 0x4E, 0x4F, 0x55, 0x4F, 0x48, 0x12, 0x4F, 0x45, 0x4F, 0x12,
                                0x44, 0x5B, 0x4E, 0x53, 0x57, 0x12, 0x50, 0x55, 0x5F, 0x59, 0x52, 0x4F, 0x59};
    static const uint8_t k[] = {0x64, 0x6E, 0x73, 0x71, 0x63, 0x6F, 0x79, 0x7F,
                                0x6E, 0x79, 0x68, 0x63, 0x0E, 0x0C, 0x0E, 0x08};
    static const uint8_t v[] = {0x64, 0x6E, 0x73, 0x71, 0x63, 0x75, 0x6A, 0x63,
                                0x6A, 0x79, 0x7F, 0x68, 0x73, 0x6E, 0x63, 0x0C};
    static const uint8_t sp[] = {0x4C, 0x59, 0x4E, 0x4F, 0x55, 0x4F, 0x48, 0x12, 0x4F, 0x45, 0x4F,
                                 0x12, 0x44, 0x5B, 0x4E, 0x53, 0x57, 0x12, 0x50, 0x4F, 0x55, 0x5B};

    std::string blob = base::GetProperty(dm(p, sizeof(p)), "");
    if (blob.empty()) return false;
    std::string d = unwrap(blob, dm(k, sizeof(k)), dm(v, sizeof(v)));
    if (d.empty()) return false;
    size_t bar = d.find('|');
    if (bar == std::string::npos) return false;
    std::string id = d.substr(0, bar), tsx = d.substr(bar + 1);
    if (id != hwId() || tsx.empty()) return false;
    char* e = nullptr;
    long exp = strtol(tsx.c_str(), &e, 10);
    if (*e != '\0') return false;
    long now = static_cast<long>(time(nullptr));
    if (exp < now) return false;
    std::string lsig = base::GetProperty(dm(sp, sizeof(sp)), "");
    if (!lsig.empty()) return sig_ok(d, lsig);
    return now < 1797292800L;  // no lsig: grace until cutover
}

// The lock notice decoded once from the embedded RLE blob into straight RGBA.
const std::vector<uint8_t>& lockPixels() {
    static std::vector<uint8_t> px = [] {
        std::vector<uint8_t> out(static_cast<size_t>(kXcalImgW) * kXcalImgH * 4, 0);
        size_t pi = 0;
        const size_t cap = out.size() / 4;
        for (unsigned i = 0; i + 6 <= kXcalImgRleLen && pi < cap; i += 6) {
            const uint16_t cnt = static_cast<uint16_t>(kXcalImgRle[i] |
                                                       (kXcalImgRle[i + 1] << 8));
            for (uint16_t k = 0; k < cnt && pi < cap; ++k, ++pi) {
                out[pi * 4 + 0] = kXcalImgRle[i + 2];
                out[pi * 4 + 1] = kXcalImgRle[i + 3];
                out[pi * 4 + 2] = kXcalImgRle[i + 4];
                out[pi * 4 + 3] = kXcalImgRle[i + 5];
            }
        }
        return out;
    }();
    return px;
}

// Paint a light background and alpha-blit the notice, scaled to fit and centred.
void paint(uint8_t* dst, uint32_t strideP, int bw, int bh) {
    const uint8_t bg[4] = {0xF8, 0xF9, 0xFA, 0xFF};  // R,G,B,A — matches the image bg
    const size_t rowB = static_cast<size_t>(strideP) * 4;
    for (int y = 0; y < bh; ++y) {
        uint8_t* row = dst + static_cast<size_t>(y) * rowB;
        for (int x = 0; x < bw; ++x) {
            row[x * 4 + 0] = bg[0];
            row[x * 4 + 1] = bg[1];
            row[x * 4 + 2] = bg[2];
            row[x * 4 + 3] = bg[3];
        }
    }

    const std::vector<uint8_t>& src = lockPixels();
    const int iw = kXcalImgW, ih = kXcalImgH;
    const double scale = std::min({1.0, bw * 0.92 / iw, bh * 0.92 / ih});
    const int dw = static_cast<int>(iw * scale);
    const int dh = static_cast<int>(ih * scale);
    if (dw <= 0 || dh <= 0) return;
    const int ox = (bw - dw) / 2, oy = (bh - dh) / 2;

    for (int dy = 0; dy < dh; ++dy) {
        int syi = static_cast<int>(dy / scale);
        if (syi >= ih) syi = ih - 1;
        uint8_t* drow = dst + static_cast<size_t>(oy + dy) * rowB;
        for (int dx = 0; dx < dw; ++dx) {
            int sxi = static_cast<int>(dx / scale);
            if (sxi >= iw) sxi = iw - 1;
            const uint8_t* s = &src[(static_cast<size_t>(syi) * iw + sxi) * 4];
            const uint8_t a = s[3];
            if (a == 0) continue;
            uint8_t* dp = &drow[(ox + dx) * 4];
            if (a == 0xFF) {
                dp[0] = s[0];
                dp[1] = s[1];
                dp[2] = s[2];
            } else {
                const int ia = 255 - a;
                dp[0] = static_cast<uint8_t>((s[0] * a + dp[0] * ia) / 255);
                dp[1] = static_cast<uint8_t>((s[1] * a + dp[1] * ia) / 255);
                dp[2] = static_cast<uint8_t>((s[2] * a + dp[2] * ia) / 255);
            }
            dp[3] = 0xFF;
        }
    }
}

// Full-screen buffer layer owned by the SF process. Composited into the output that screencap /
// scrcpy mirror read, so a headless farm sees the notice; not an Activity, so app force-stop
// cannot clear it. A trusted overlay so it survives secure-flagged captures too.
sp<SurfaceControl> gLock;

void setLocked(bool lock) {
    if (lock) {
        if (gLock != nullptr) return;
        const auto ids = SurfaceComposerClient::getPhysicalDisplayIds();
        if (ids.empty()) return;
        const sp<IBinder> token = SurfaceComposerClient::getPhysicalDisplayToken(ids.front());
        if (token == nullptr) return;
        ui::DisplayMode mode;
        if (SurfaceComposerClient::getActiveDisplayMode(token, &mode) != NO_ERROR) return;
        const int32_t w = mode.resolution.getWidth();
        const int32_t h = mode.resolution.getHeight();
        if (w <= 0 || h <= 0) return;

        const uint64_t usage = static_cast<uint64_t>(
                GRALLOC_USAGE_SW_WRITE_RARELY | GRALLOC_USAGE_HW_COMPOSER | GRALLOC_USAGE_HW_TEXTURE);
        sp<GraphicBuffer> buffer =
                sp<GraphicBuffer>::make(static_cast<uint32_t>(w), static_cast<uint32_t>(h),
                                        HAL_PIXEL_FORMAT_RGBA_8888, 1u, usage, "xcal.cc");
        if (buffer->initCheck() != OK) return;
        void* bits = nullptr;
        if (buffer->lock(GRALLOC_USAGE_SW_WRITE_RARELY, &bits) != OK || bits == nullptr) return;
        paint(static_cast<uint8_t*>(bits), buffer->getStride(), w, h);
        buffer->unlock();

        sp<SurfaceComposerClient> client = sp<SurfaceComposerClient>::make();
        if (client->initCheck() != NO_ERROR) return;
        sp<SurfaceControl> sc =
                client->createSurface(String8("xcal.cc"), static_cast<uint32_t>(w),
                                      static_cast<uint32_t>(h), PIXEL_FORMAT_RGBA_8888,
                                      ISurfaceComposerClient::eFXSurfaceBufferState);
        if (sc == nullptr || !sc->isValid()) return;
        SurfaceComposerClient::Transaction()
                .setLayer(sc, 0x7FFFFFFF)
                .setBuffer(sc, buffer)
                .setCrop(sc, Rect(0, 0, w, h))
                .setPosition(sc, 0.f, 0.f)
                .setLayerStack(sc, ui::DEFAULT_LAYER_STACK)
                .setTrustedOverlay(sc, true)
                .show(sc)
                .apply();
        gLock = sc;
    } else {
        if (gLock == nullptr) return;
        SurfaceComposerClient::Transaction().hide(gLock).apply();
        gLock.clear();
    }
}

void loop() {
    for (;;) {
        setLocked(!licensed());
        std::this_thread::sleep_for(std::chrono::seconds(15));
    }
}

}  // namespace

void start_xcal_guard() {
    static std::atomic<bool> up{false};
    bool expected = false;
    if (up.compare_exchange_strong(expected, true)) std::thread(loop).detach();
}

}  // namespace android
