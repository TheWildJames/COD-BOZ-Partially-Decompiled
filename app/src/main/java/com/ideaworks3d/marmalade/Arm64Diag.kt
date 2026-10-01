package com.ideaworks3d.marmalade

import android.util.Log

/**
 * Diagnostic for the arm64 Pixel 8 launch crash.
 *
 * Observed sequence on a Pixel 8 (Android 17, kernel 6.1.157-android14-Wild):
 *
 *   1. LoaderView.surfaceChanged() -> LoaderActivity.LoaderThread() -> NPE
 *      at LoaderActivity.kt:44, because m_LoaderThread is still null.
 *   2. The exception escapes into SurfaceView.updateSurface(), leaving the
 *      engine's GL thread without a valid loader.
 *   3. ActivityThread then schedules a relaunch, and on the relaunch path the
 *      native engine calls pthread_once() with a null once_control
 *      (x0 == 0), which faults inside bionic at pthread_mutex_trylock+4.
 *      Crash pc in libs3e_android.so is 0xbff0c.
 *
 * Step 1 is the actual bug and it is in the Kotlin wrapper, not in the ARM32
 * game payload. surfaceChanged() can run before startLoader() has assigned
 * m_LoaderThread, because the SurfaceView becomes visible as soon as
 * setContentView() runs in onCreate(), while startLoader() is deferred.
 *
 * The original Java used a null-returning accessor here; the Kotlin port
 * turned it into `m_LoaderThread!!`, which throws instead. Restoring the
 * original null-returning behaviour is the minimal correct fix.
 */
object Arm64Diag {
    private const val TAG = "BOZ-arm64-diag"

    fun log(msg: String) {
        Log.i(TAG, msg)
    }

    /** True once the loader thread exists, so surface callbacks can proceed. */
    @JvmStatic
    fun loaderReady(activity: LoaderActivity?): Boolean {
        val ok = activity?.hasLoaderThread() == true
        if (!ok) {
            log("surface callback with m_LoaderThread == null (deferring)")
        }
        return ok
    }
}
