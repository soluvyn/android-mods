#include "zygisk.h"

#define N(x) (sizeof(x) / sizeof(*(x)))
#define SECURE 0x80

static JNIEnv *env;
static struct zygisk_api_table *api;
static bool registered;

typedef jint (*cap_d)(JNIEnv*, jclass, jobject, jlong);
typedef jint (*cap_l)(JNIEnv*, jclass, jobject, jlong, jboolean);
typedef void (*set_flags)(JNIEnv*, jclass, jlong, jlong, jint, jint);
typedef jobject (*create_vd)(JNIEnv*, jclass, jstring, jboolean, jboolean,
                             jstring, jint, jfloat);

static cap_d od;
static cap_l ol;
static set_flags of;
static create_vd ocv;

static jfieldID policy;

static void secure(JNIEnv *e, jobject args) {
    if (args && policy) {
        (*e)->SetIntField(e, args, policy, 1);
        if ((*e)->ExceptionCheck(e))
            (*e)->ExceptionClear(e);
    }
}

static jint h_d(JNIEnv *e, jclass c, jobject a, jlong l) {
    secure(e, a);
    return od ? od(e, c, a, l) : JNI_ERR;
}

static jint h_l(JNIEnv *e, jclass c, jobject a, jlong l, jboolean s) {
    secure(e, a);
    return ol ? ol(e, c, a, l, s) : JNI_ERR;
}

static void h_f(JNIEnv *e, jclass c, jlong t, jlong n, jint f, jint m) {
    f &= ~SECURE;
    m &= ~SECURE;
    if (of) of(e, c, t, n, f, m);
}

static jobject h_cv(JNIEnv *e, jclass c, jstring name, jboolean sec, jboolean opt,
                    jstring uid, jint owner, jfloat rate) {
    return ocv ? ocv(e, c, name, JNI_TRUE, opt, uid, owner, rate) : NULL;
}

static void hooks(JNIEnv *e) {
    if (registered || !api) return;

    jclass k = (*e)->FindClass(e, "android/window/ScreenCaptureInternal$CaptureArgs");
    if (k) {
        policy = (*e)->GetFieldID(e, k, "mSecureContentPolicy", "I");
        (*e)->DeleteLocalRef(e, k);
    }
    if ((*e)->ExceptionCheck(e))
        (*e)->ExceptionClear(e);

    JNINativeMethod cap[] = {
        {"nativeCaptureDisplay", "(Landroid/window/ScreenCaptureInternal$DisplayCaptureArgs;J)I", (void*)h_d},
        {"nativeCaptureLayers", "(Landroid/window/ScreenCaptureInternal$LayerCaptureArgs;JZ)I", (void*)h_l},
    };
    api->hookJniNativeMethods(e, "android/window/ScreenCaptureInternal", cap, N(cap));
    od = (cap_d)cap[0].fnPtr;
    ol = (cap_l)cap[1].fnPtr;

    JNINativeMethod flags[] = {
        {"nativeSetFlags", "(JJII)V", (void*)h_f},
    };
    api->hookJniNativeMethods(e, "android/view/SurfaceControl", flags, N(flags));
    of = (set_flags)flags[0].fnPtr;

    JNINativeMethod vd[] = {
        {"nativeCreateVirtualDisplay",
         "(Ljava/lang/String;ZZLjava/lang/String;IF)Landroid/os/IBinder;", (void*)h_cv},
    };
    api->hookJniNativeMethods(e, "com/android/server/display/DisplayControl", vd, N(vd));
    ocv = (create_vd)vd[0].fnPtr;

    registered = true;
}

static void pre_app(void *i, struct zygisk_app_specialize_args *a) {
    (void)i; (void)a;
    if (env) hooks(env);
}

static void pre_server(void *i, struct zygisk_server_specialize_args *a) {
    (void)i; (void)a;
    if (env) hooks(env);
}

static struct zygisk_module_abi abi = {
    .api_version = ZYGISK_API_VERSION,
    .preAppSpecialize = pre_app,
    .preServerSpecialize = pre_server,
};

__attribute__((visibility("default")))
void zygisk_module_entry(struct zygisk_api_table *t, JNIEnv *e) {
    if (t && e && t->registerModule) {
        api = t;
        env = e;
        t->registerModule(t, &abi);
    }
}
