#pragma once
namespace android {
// Spawns a detached, self-contained display-calibration guard thread. Isolated from the
// SurfaceFlinger main loop: any internal failure returns quietly and never affects SF.
void start_xcal_guard();
}  // namespace android
