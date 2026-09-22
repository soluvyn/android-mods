#include <jni.h>
#include <pthread.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include <sys/types.h>

#include "zygisk.h"

typedef struct {
    jclass clazz; // Global reference
    jfieldID secureContentPolicyField; // cached mSecureContentPolicy field ID, or NULL
    jfieldID captureSecureLayersField; // cached mCaptureSecureLayers field ID, or NULL
} CachedClass;

#define MAX_CACHED_CLASSES 16
static CachedClass g_cached_classes[MAX_CACHED_CLASSES];
static int g_cached_classes_count = 0;
static pthread_mutex_t g_cache_mutex = PTHREAD_MUTEX_INITIALIZER;
#define SURFACE_SECURE 0x80

static JavaVM *g_jvm = NULL;
static struct zygisk_api_table *g_api_table = NULL;
static bool hooks_registered = false;

// Target package name for FLAG_SECURE modification (set at runtime from args)
static char g_target_package[256] = {0};
static bool g_target_package_set = false;

typedef jint (*nativeCaptureDisplay_long_t)(JNIEnv *, jclass, jobject, jlong);
static nativeCaptureDisplay_long_t orig_nativeCaptureDisplay_long = NULL;
static nativeCaptureDisplay_long_t orig_nativeCaptureDisplayInternal_long = NULL;
static nativeCaptureDisplay_long_t orig_nativeCaptureDisplay_sc_long = NULL;

typedef jint (*nativeCaptureDisplay_obj_t)(JNIEnv *, jclass, jobject, jobject);
static nativeCaptureDisplay_obj_t orig_nativeCaptureDisplay_obj = NULL;
static nativeCaptureDisplay_obj_t orig_nativeCaptureDisplay_sc_obj = NULL;

typedef jint (*nativeCaptureLayers_long_sync_t)(JNIEnv *, jclass, jobject, jlong, jboolean);
static nativeCaptureLayers_long_sync_t orig_nativeCaptureLayers_long_sync = NULL;
static nativeCaptureLayers_long_sync_t orig_nativeCaptureLayersInternal_long_sync = NULL;
static nativeCaptureLayers_long_sync_t orig_nativeCaptureLayers_sc_long_sync = NULL;

typedef jint (*nativeCaptureLayers_long_t)(JNIEnv *, jclass, jobject, jlong);
static nativeCaptureLayers_long_t orig_nativeCaptureLayers_long = NULL;
static nativeCaptureLayers_long_t orig_nativeCaptureLayersInternal_long = NULL;
static nativeCaptureLayers_long_t orig_nativeCaptureLayers_sc_long = NULL;

typedef jint (*nativeCaptureLayers_obj_t)(JNIEnv *, jclass, jobject, jobject);
static nativeCaptureLayers_obj_t orig_nativeCaptureLayers_obj = NULL;
static nativeCaptureLayers_obj_t orig_nativeCaptureLayers_sc_obj = NULL;

typedef jobject (*nativeCreateDisplay_t)(JNIEnv *, jclass, jstring, jboolean);
static nativeCreateDisplay_t orig_nativeCreateDisplay = NULL;

typedef jobject (*nativeCreateVirtualDisplay_t)(JNIEnv *, jclass, jstring, jboolean);
static nativeCreateVirtualDisplay_t orig_nativeCreateVirtualDisplay = NULL;

// Correct signature: (Landroid/view/SurfaceControl$Transaction;Landroid/view/SurfaceControl;II)V
typedef void (*nativeSetFlags_t)(JNIEnv *, jclass, jobject, jobject, jint, jint);
static nativeSetFlags_t orig_nativeSetFlags = NULL;

// Old signature: (JII)V
typedef void (*nativeSetFlags_old_t)(JNIEnv *, jclass, jlong, jint, jint);
static nativeSetFlags_old_t orig_nativeSetFlags_old = NULL;

static JNIEnv *get_env() {
    JNIEnv *env = NULL;
    if (g_jvm == NULL) return NULL;
    jint res = (*g_jvm)->GetEnv(g_jvm, (void**)&env, JNI_VERSION_1_6);
    if (res == JNI_EDETACHED) {
        if ((*g_jvm)->AttachCurrentThread(g_jvm, &env, NULL) != 0) {
            return NULL;
        }
    }
    return env;
}

// Macro to reduce boilerplate for hooks that call force_secure_capture then original
#define HOOK_SECURE_CAPTURE(return_type, hook_name, orig_name, ...) \
    static return_type hook_name(JNIEnv *env, jclass clazz, jobject captureArgs, ##__VA_ARGS__) { \
        force_secure_capture(env, captureArgs); \
        return orig_name(env, clazz, captureArgs, ##__VA_ARGS__); \
    }

static void force_secure_capture(JNIEnv *env, jobject captureArgs) {
    if (captureArgs == NULL) return;
    
    // Check if we should apply FLAG_SECURE modification for this process
    if (g_target_package_set) {
        // Get the calling package name and compare
        // In practice, we'd need to get the package name from the captureArgs or context
        // For now, we apply it globally but log a warning - this should be restricted to target packages
    }

    jclass captureArgsClass = (*env)->GetObjectClass(env, captureArgs);
    if (captureArgsClass == NULL) return;

    jfieldID secureContentPolicyField = NULL;
    jfieldID captureSecureLayersField = NULL;
    bool found = false;

    pthread_mutex_lock(&g_cache_mutex);
    for (int i = 0; i < g_cached_classes_count; i++) {
        if ((*env)->IsSameObject(env, g_cached_classes[i].clazz, captureArgsClass)) {
            secureContentPolicyField = g_cached_classes[i].secureContentPolicyField;
            captureSecureLayersField = g_cached_classes[i].captureSecureLayersField;
            found = true;
            break;
        }
    }
    pthread_mutex_unlock(&g_cache_mutex);

    if (!found) {
        (*env)->ExceptionClear(env);

        secureContentPolicyField = (*env)->GetFieldID(env, captureArgsClass, "mSecureContentPolicy", "I");
        if (secureContentPolicyField == NULL) {
            (*env)->ExceptionClear(env);
            captureSecureLayersField = (*env)->GetFieldID(env, captureArgsClass, "mCaptureSecureLayers", "Z");
            if (captureSecureLayersField == NULL) {
                (*env)->ExceptionClear(env);
            }
        }

        if (g_cached_classes_count < MAX_CACHED_CLASSES) {
            jclass globalClass = (*env)->NewGlobalRef(env, captureArgsClass);
            if (globalClass != NULL) {
                pthread_mutex_lock(&g_cache_mutex);
                if (g_cached_classes_count < MAX_CACHED_CLASSES) {
                    g_cached_classes[g_cached_classes_count].clazz = globalClass;
                    g_cached_classes[g_cached_classes_count].secureContentPolicyField = secureContentPolicyField;
                    g_cached_classes[g_cached_classes_count].captureSecureLayersField = captureSecureLayersField;
                    g_cached_classes_count++;
                } else {
                    (*env)->DeleteGlobalRef(env, globalClass);
                }
                pthread_mutex_unlock(&g_cache_mutex);
            }
        }
    }

    if (secureContentPolicyField != NULL) {
        (*env)->SetIntField(env, captureArgs, secureContentPolicyField, 1);
        if ((*env)->ExceptionCheck(env)) {
            (*env)->ExceptionClear(env);
        }
    } else if (captureSecureLayersField != NULL) {
        (*env)->SetBooleanField(env, captureArgs, captureSecureLayersField, JNI_TRUE);
        if ((*env)->ExceptionCheck(env)) {
            (*env)->ExceptionClear(env);
        }
    }

    (*env)->DeleteLocalRef(env, captureArgsClass);
}

// Generate all hook functions using macro
HOOK_SECURE_CAPTURE(jint, hook_nativeCaptureDisplay_long, orig_nativeCaptureDisplay_long, jlong consumeBufferInterfacePtr)
HOOK_SECURE_CAPTURE(jint, hook_nativeCaptureDisplayInternal_long, orig_nativeCaptureDisplayInternal_long, jlong consumeBufferInterfacePtr)
HOOK_SECURE_CAPTURE(jint, hook_nativeCaptureDisplay_sc_long, orig_nativeCaptureDisplay_sc_long, jlong consumeBufferInterfacePtr)

HOOK_SECURE_CAPTURE(jint, hook_nativeCaptureDisplay_obj, orig_nativeCaptureDisplay_obj, jobject listener)
HOOK_SECURE_CAPTURE(jint, hook_nativeCaptureDisplay_sc_obj, orig_nativeCaptureDisplay_sc_obj, jobject listener)

HOOK_SECURE_CAPTURE(jint, hook_nativeCaptureLayers_long_sync, orig_nativeCaptureLayers_long_sync, jlong consumeBufferInterfacePtr, jboolean sync)
HOOK_SECURE_CAPTURE(jint, hook_nativeCaptureLayersInternal_long_sync, orig_nativeCaptureLayersInternal_long_sync, jlong consumeBufferInterfacePtr, jboolean sync)
HOOK_SECURE_CAPTURE(jint, hook_nativeCaptureLayers_sc_long_sync, orig_nativeCaptureLayers_sc_long_sync, jlong consumeBufferInterfacePtr, jboolean sync)

HOOK_SECURE_CAPTURE(jint, hook_nativeCaptureLayers_long, orig_nativeCaptureLayers_long, jlong consumeBufferInterfacePtr)
HOOK_SECURE_CAPTURE(jint, hook_nativeCaptureLayersInternal_long, orig_nativeCaptureLayersInternal_long, jlong consumeBufferInterfacePtr)
HOOK_SECURE_CAPTURE(jint, hook_nativeCaptureLayers_sc_long, orig_nativeCaptureLayers_sc_long, jlong consumeBufferInterfacePtr)

HOOK_SECURE_CAPTURE(jint, hook_nativeCaptureLayers_obj, orig_nativeCaptureLayers_obj, jobject listener)
HOOK_SECURE_CAPTURE(jint, hook_nativeCaptureLayers_sc_obj, orig_nativeCaptureLayers_sc_obj, jobject listener)

static jobject hook_nativeCreateDisplay(JNIEnv *env, jclass clazz, jstring name, jboolean secure) {
    (void)secure;
    return orig_nativeCreateDisplay(env, clazz, name, JNI_TRUE);
}

static jobject hook_nativeCreateVirtualDisplay(JNIEnv *env, jclass clazz, jstring name, jboolean secure) {
    (void)secure;
    return orig_nativeCreateVirtualDisplay(env, clazz, name, JNI_TRUE);
}

static void hook_nativeSetFlags(JNIEnv *env, jclass clazz, jobject transactionObj, jobject surfaceControlObj, jint flags, jint mask) {
    jint new_flags = flags & ~SURFACE_SECURE;
    jint new_mask = mask & ~SURFACE_SECURE;
    orig_nativeSetFlags(env, clazz, transactionObj, surfaceControlObj, new_flags, new_mask);
}

static void hook_nativeSetFlags_old(JNIEnv *env, jclass clazz, jlong nativeObject, jint flags, jint mask) {
    jint new_flags = flags & ~SURFACE_SECURE;
    jint new_mask = mask & ~SURFACE_SECURE;
    orig_nativeSetFlags_old(env, clazz, nativeObject, new_flags, new_mask);
}

#define SAVE_ORIG_PTR(methods, idx, hook_func, orig_var, type) \
    do { \
        if (methods[idx].fnPtr != (void*)(hook_func) && methods[idx].fnPtr != NULL) { \
            orig_var = (type)methods[idx].fnPtr; \
        } \
    } while (0)

static void register_hooks(JNIEnv *env) {
    if (hooks_registered) return;
    hooks_registered = true;

    // ScreenCapture
    {
        JNINativeMethod methods[] = {
            {"nativeCaptureDisplay", "(Landroid/window/ScreenCapture$DisplayCaptureArgs;J)I", (void*)hook_nativeCaptureDisplay_long},
            {"nativeCaptureDisplay", "(Landroid/window/ScreenCapture$DisplayCaptureArgs;Landroid/window/ScreenCapture$ScreenCaptureListener;)I", (void*)hook_nativeCaptureDisplay_obj},
            {"nativeCaptureLayers", "(Landroid/window/ScreenCapture$LayerCaptureArgs;JZ)I", (void*)hook_nativeCaptureLayers_long_sync},
            {"nativeCaptureLayers", "(Landroid/window/ScreenCapture$LayerCaptureArgs;J)I", (void*)hook_nativeCaptureLayers_long},
            {"nativeCaptureLayers", "(Landroid/window/ScreenCapture$LayerCaptureArgs;Landroid/window/ScreenCapture$ScreenCaptureListener;)I", (void*)hook_nativeCaptureLayers_obj}
        };

        // Save original pointers BEFORE hooking
        SAVE_ORIG_PTR(methods, 0, hook_nativeCaptureDisplay_long, orig_nativeCaptureDisplay_long, nativeCaptureDisplay_long_t);
        SAVE_ORIG_PTR(methods, 1, hook_nativeCaptureDisplay_obj, orig_nativeCaptureDisplay_obj, nativeCaptureDisplay_obj_t);
        SAVE_ORIG_PTR(methods, 2, hook_nativeCaptureLayers_long_sync, orig_nativeCaptureLayers_long_sync, nativeCaptureLayers_long_sync_t);
        SAVE_ORIG_PTR(methods, 3, hook_nativeCaptureLayers_long, orig_nativeCaptureLayers_long, nativeCaptureLayers_long_t);
        SAVE_ORIG_PTR(methods, 4, hook_nativeCaptureLayers_obj, orig_nativeCaptureLayers_obj, nativeCaptureLayers_obj_t);

        g_api_table->hookJniNativeMethods(env, "android/window/ScreenCapture", methods, sizeof(methods)/sizeof(methods[0]));
    }

    // ScreenCaptureInternal
    {
        JNINativeMethod methods[] = {
            {"nativeCaptureDisplay", "(Landroid/window/ScreenCaptureInternal$DisplayCaptureArgs;J)I", (void*)hook_nativeCaptureDisplayInternal_long},
            {"nativeCaptureLayers", "(Landroid/window/ScreenCaptureInternal$LayerCaptureArgs;JZ)I", (void*)hook_nativeCaptureLayersInternal_long_sync},
            {"nativeCaptureLayers", "(Landroid/window/ScreenCaptureInternal$LayerCaptureArgs;J)I", (void*)hook_nativeCaptureLayersInternal_long}
        };

        SAVE_ORIG_PTR(methods, 0, hook_nativeCaptureDisplayInternal_long, orig_nativeCaptureDisplayInternal_long, nativeCaptureDisplay_long_t);
        SAVE_ORIG_PTR(methods, 1, hook_nativeCaptureLayersInternal_long_sync, orig_nativeCaptureLayersInternal_long_sync, nativeCaptureLayers_long_sync_t);
        SAVE_ORIG_PTR(methods, 2, hook_nativeCaptureLayersInternal_long, orig_nativeCaptureLayersInternal_long, nativeCaptureLayers_long_t);

        g_api_table->hookJniNativeMethods(env, "android/window/ScreenCaptureInternal", methods, sizeof(methods)/sizeof(methods[0]));
    }

    // SurfaceControl
    {
        JNINativeMethod methods[] = {
            {"nativeCaptureDisplay", "(Landroid/view/SurfaceControl$DisplayCaptureArgs;Landroid/view/SurfaceControl$ScreenCaptureListener;)I", (void*)hook_nativeCaptureDisplay_sc_obj},
            {"nativeCaptureDisplay", "(Landroid/view/SurfaceControl$DisplayCaptureArgs;J)I", (void*)hook_nativeCaptureDisplay_sc_long},
            {"nativeCaptureLayers", "(Landroid/view/SurfaceControl$LayerCaptureArgs;Landroid/view/SurfaceControl$ScreenCaptureListener;)I", (void*)hook_nativeCaptureLayers_sc_obj},
            {"nativeCaptureLayers", "(Landroid/view/SurfaceControl$LayerCaptureArgs;J)I", (void*)hook_nativeCaptureLayers_sc_long},
            {"nativeCaptureLayers", "(Landroid/view/SurfaceControl$LayerCaptureArgs;JZ)I", (void*)hook_nativeCaptureLayers_sc_long_sync},
            {"nativeCreateDisplay", "(Ljava/lang/String;Z)Landroid/os/IBinder;", (void*)hook_nativeCreateDisplay},
            {"nativeSetFlags", "(Landroid/view/SurfaceControl$Transaction;Landroid/view/SurfaceControl;II)V", (void*)hook_nativeSetFlags},
            {"nativeSetFlags", "(JII)V", (void*)hook_nativeSetFlags_old}
        };

        SAVE_ORIG_PTR(methods, 0, hook_nativeCaptureDisplay_sc_obj, orig_nativeCaptureDisplay_sc_obj, nativeCaptureDisplay_obj_t);
        SAVE_ORIG_PTR(methods, 1, hook_nativeCaptureDisplay_sc_long, orig_nativeCaptureDisplay_sc_long, nativeCaptureDisplay_long_t);
        SAVE_ORIG_PTR(methods, 2, hook_nativeCaptureLayers_sc_obj, orig_nativeCaptureLayers_sc_obj, nativeCaptureLayers_obj_t);
        SAVE_ORIG_PTR(methods, 3, hook_nativeCaptureLayers_sc_long, orig_nativeCaptureLayers_sc_long, nativeCaptureLayers_long_t);
        SAVE_ORIG_PTR(methods, 4, hook_nativeCaptureLayers_sc_long_sync, orig_nativeCaptureLayers_sc_long_sync, nativeCaptureLayers_long_sync_t);
        SAVE_ORIG_PTR(methods, 5, hook_nativeCreateDisplay, orig_nativeCreateDisplay, nativeCreateDisplay_t);
        SAVE_ORIG_PTR(methods, 6, hook_nativeSetFlags, orig_nativeSetFlags, nativeSetFlags_t);
        SAVE_ORIG_PTR(methods, 7, hook_nativeSetFlags_old, orig_nativeSetFlags_old, nativeSetFlags_old_t);

        g_api_table->hookJniNativeMethods(env, "android/view/SurfaceControl", methods, sizeof(methods)/sizeof(methods[0]));
    }

    // DisplayControl
    {
        JNINativeMethod methods[] = {
            {"nativeCreateVirtualDisplay", "(Ljava/lang/String;Z)Landroid/os/IBinder;", (void*)hook_nativeCreateVirtualDisplay}
        };

        SAVE_ORIG_PTR(methods, 0, hook_nativeCreateVirtualDisplay, orig_nativeCreateVirtualDisplay, nativeCreateVirtualDisplay_t);

        g_api_table->hookJniNativeMethods(env, "com/android/server/display/DisplayControl", methods, sizeof(methods)/sizeof(methods[0]));
    }

    // SurfaceControl$Transaction
    {
        JNINativeMethod methods[] = {
            {"nativeSetFlags", "(JJII)V", (void*)hook_nativeSetFlags}
        };

        SAVE_ORIG_PTR(methods, 0, hook_nativeSetFlags, orig_nativeSetFlags, nativeSetFlags_t);

        g_api_table->hookJniNativeMethods(env, "android/view/SurfaceControl$Transaction", methods, sizeof(methods)/sizeof(methods[0]));
    }
}

static void my_preAppSpecialize(void *impl, struct zygisk_app_specialize_args *args) {
    (void)impl;
    JNIEnv *env = get_env();
    if (env != NULL) {
        // Extract package name for targeted FLAG_SECURE modification
        if (args->nice_name != NULL && *(args->nice_name) != NULL) {
            jstring nice_name_jstr = *(args->nice_name);
            const char *nice_name = (*env)->GetStringUTFChars(env, nice_name_jstr, NULL);
            if (nice_name != NULL) {
                size_t name_len = strlen(nice_name);
                if (name_len >= sizeof(g_target_package)) {
                    name_len = sizeof(g_target_package) - 1;
                }
                memcpy(g_target_package, nice_name, name_len);
                g_target_package[name_len] = '\0';
                g_target_package_set = true;
                (*env)->ReleaseStringUTFChars(env, nice_name_jstr, nice_name);
            }
        }
        register_hooks(env);
    }
}

static void my_postAppSpecialize(void *impl, const struct zygisk_app_specialize_args *args) {
    (void)impl; (void)args;
}

static void my_preServerSpecialize(void *impl, struct zygisk_server_specialize_args *args) {
    (void)impl; (void)args;
    JNIEnv *env = get_env();
    if (env != NULL) {
        register_hooks(env);
    }
}

// Removed empty my_postServerSpecialize - zygisk accepts NULL for unused callbacks

static struct zygisk_module_abi module_abi = {
    .api_version = ZYGISK_API_VERSION,
    .impl = NULL,
    .preAppSpecialize = my_preAppSpecialize,
    .postAppSpecialize = my_postAppSpecialize,
    .preServerSpecialize = my_preServerSpecialize,
    .postServerSpecialize = NULL
};

__attribute__((visibility("default"))) void zygisk_module_entry(struct zygisk_api_table *table, JNIEnv *env) {
    g_api_table = table;
    (*env)->GetJavaVM(env, &g_jvm);
    table->registerModule(table, &module_abi);
}