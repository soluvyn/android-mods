#include <jni.h>
#include <stdbool.h>
#include "zygisk.h"

#define N(x) (sizeof(x) / sizeof(*(x)))
#define SECURE 0x80

static JNIEnv *env;
static struct zygisk_api_table *api;
static bool registered;

typedef jint (*cap_d)(JNIEnv*,jclass,jobject,jlong);
typedef jint (*cap_o)(JNIEnv*,jclass,jobject,jobject);
typedef jint (*cap_s)(JNIEnv*,jclass,jobject,jlong,jboolean);
typedef jobject (*create_d)(JNIEnv*,jclass,jstring,jboolean);
typedef void (*flags)(JNIEnv*,jclass,jobject,jobject,jint,jint);
typedef void (*flags_j)(JNIEnv*,jclass,jlong,jint,jint);
typedef void (*flags_t)(JNIEnv*,jclass,jlong,jlong,jint,jint);

static cap_d od, odi, od_sc, ol, oli, ol_sc;
static cap_o oo, oo_sc, olo, olo_sc;
static cap_s os, osi, os_sc;
static create_d ocd, ocv;
static flags of;
static flags_j of_old;
static flags_t oft;

static jfieldID d_policy, d_layers;
static jfieldID l_policy, l_layers;
static jfieldID sd_policy, sd_layers;

static void secure(JNIEnv *e, jobject o, jfieldID policy, jfieldID layers) {
    if (!o) return;

    if (policy)
        (*e)->SetIntField(e, o, policy, 1);
    else if (layers)
        (*e)->SetBooleanField(e, o, layers, JNI_TRUE);

    if ((*e)->ExceptionCheck(e))
        (*e)->ExceptionClear(e);
}

#define CAP(name, orig, p, l, t)                       \
static jint name(JNIEnv *e,jclass c,jobject a,t x) {   \
    secure(e,a,p,l);                                   \
    return orig ? orig(e,c,a,x) : JNI_ERR;             \
}

#define CAPS(name, orig, p, l, t)                             \
static jint name(JNIEnv *e,jclass c,jobject a,t x,jboolean s) { \
    secure(e,a,p,l);                                           \
    return orig ? orig(e,c,a,x,s) : JNI_ERR;                   \
}

CAP(h_d,   od,    d_policy,d_layers,jlong)
CAP(h_di,  odi,   l_policy,l_layers,jlong)
CAP(h_ds,  od_sc, sd_policy,sd_layers,jlong)
CAP(h_do,  oo,    d_policy,d_layers,jobject)
CAP(h_dso, oo_sc, sd_policy,sd_layers,jobject)

CAP(h_l,   ol,    d_policy,d_layers,jlong)
CAP(h_li,  oli,   l_policy,l_layers,jlong)
CAP(h_ls,  ol_sc, sd_policy,sd_layers,jlong)
CAP(h_lo,  olo,   d_policy,d_layers,jobject)
CAP(h_lso, olo_sc, sd_policy,sd_layers,jobject)

CAPS(h_s,   os,    d_policy,d_layers,jlong)
CAPS(h_si,  osi,   l_policy,l_layers,jlong)
CAPS(h_ss,  os_sc, sd_policy,sd_layers,jlong)

static jobject h_cd(JNIEnv *e,jclass c,jstring n,jboolean s) {
    return ocd ? ocd(e,c,n,JNI_TRUE) : NULL;
}

static jobject h_cv(JNIEnv *e,jclass c,jstring n,jboolean s) {
    return ocv ? ocv(e,c,n,JNI_TRUE) : NULL;
}

static void h_f(JNIEnv *e,jclass c,jobject t,jobject s,jint f,jint m) {
    f &= ~SECURE; m &= ~SECURE;
    if (of) of(e,c,t,s,f,m);
}

static void h_fo(JNIEnv *e,jclass c,jlong o,jint f,jint m) {
    f &= ~SECURE; m &= ~SECURE;
    if (of_old) of_old(e,c,o,f,m);
}

static void h_ft(JNIEnv *e,jclass c,jlong t,jlong s,jint f,jint m) {
    f &= ~SECURE; m &= ~SECURE;
    if (oft) oft(e,c,t,s,f,m);
}

#define SAVE(m,i,o,t) ((o)=(t)(m)[i].fnPtr)

static jfieldID fid(JNIEnv *e,const char *c,const char *n,const char *s) {
    jclass k = (*e)->FindClass(e,c);
    if (!k) { (*e)->ExceptionClear(e); return NULL; }

    jfieldID f = (*e)->GetFieldID(e,k,n,s);
    if (!f) (*e)->ExceptionClear(e);

    (*e)->DeleteLocalRef(e,k);
    return f;
}

static void hooks(JNIEnv *e) {
    if (registered || !api) return;

    d_policy = fid(e,"android/window/ScreenCapture$DisplayCaptureArgs",
                   "mSecureContentPolicy","I");
    d_layers = fid(e,"android/window/ScreenCapture$DisplayCaptureArgs",
                   "mCaptureSecureLayers","Z");

    l_policy = fid(e,"android/window/ScreenCapture$LayerCaptureArgs",
                   "mSecureContentPolicy","I");
    l_layers = fid(e,"android/window/ScreenCapture$LayerCaptureArgs",
                   "mCaptureSecureLayers","Z");

    sd_policy = fid(e,"android/view/SurfaceControl$DisplayCaptureArgs",
                    "mSecureContentPolicy","I");
    sd_layers = fid(e,"android/view/SurfaceControl$DisplayCaptureArgs",
                    "mCaptureSecureLayers","Z");

    JNINativeMethod a[] = {
        {"nativeCaptureDisplay","(Landroid/window/ScreenCapture$DisplayCaptureArgs;J)I",(void*)h_d},
        {"nativeCaptureDisplay","(Landroid/window/ScreenCapture$DisplayCaptureArgs;Landroid/window/ScreenCapture$ScreenCaptureListener;)I",(void*)h_do},
        {"nativeCaptureLayers","(Landroid/window/ScreenCapture$LayerCaptureArgs;JZ)I",(void*)h_s},
        {"nativeCaptureLayers","(Landroid/window/ScreenCapture$LayerCaptureArgs;J)I",(void*)h_l},
        {"nativeCaptureLayers","(Landroid/window/ScreenCapture$LayerCaptureArgs;Landroid/window/ScreenCapture$ScreenCaptureListener;)I",(void*)h_lo}
    };

    api->hookJniNativeMethods(e,"android/window/ScreenCapture",a,N(a));
    SAVE(a,0,od,cap_d); SAVE(a,1,oo,cap_o);
    SAVE(a,2,os,cap_s); SAVE(a,3,ol,cap_d); SAVE(a,4,olo,cap_o);

    JNINativeMethod b[] = {
        {"nativeCaptureDisplay","(Landroid/window/ScreenCaptureInternal$DisplayCaptureArgs;J)I",(void*)h_di},
        {"nativeCaptureLayers","(Landroid/window/ScreenCaptureInternal$LayerCaptureArgs;JZ)I",(void*)h_si},
        {"nativeCaptureLayers","(Landroid/window/ScreenCaptureInternal$LayerCaptureArgs;J)I",(void*)h_li}
    };

    api->hookJniNativeMethods(e,"android/window/ScreenCaptureInternal",b,N(b));
    SAVE(b,0,odi,cap_d); SAVE(b,1,osi,cap_s); SAVE(b,2,oli,cap_d);

    JNINativeMethod c[] = {
        {"nativeCaptureDisplay","(Landroid/view/SurfaceControl$DisplayCaptureArgs;Landroid/view/SurfaceControl$ScreenCaptureListener;)I",(void*)h_dso},
        {"nativeCaptureDisplay","(Landroid/view/SurfaceControl$DisplayCaptureArgs;J)I",(void*)h_ds},
        {"nativeCaptureLayers","(Landroid/view/SurfaceControl$LayerCaptureArgs;Landroid/view/SurfaceControl$ScreenCaptureListener;)I",(void*)h_lso},
        {"nativeCaptureLayers","(Landroid/view/SurfaceControl$LayerCaptureArgs;J)I",(void*)h_ls},
        {"nativeCaptureLayers","(Landroid/view/SurfaceControl$LayerCaptureArgs;JZ)I",(void*)h_ss},
        {"nativeCreateDisplay","(Ljava/lang/String;Z)Landroid/os/IBinder;",(void*)h_cd},
        {"nativeSetFlags","(Landroid/view/SurfaceControl$Transaction;Landroid/view/SurfaceControl;II)V",(void*)h_f},
        {"nativeSetFlags","(JII)V",(void*)h_fo}
    };

    api->hookJniNativeMethods(e,"android/view/SurfaceControl",c,N(c));
    SAVE(c,0,oo_sc,cap_o); SAVE(c,1,od_sc,cap_d);
    SAVE(c,2,olo_sc,cap_o); SAVE(c,3,ol_sc,cap_d);
    SAVE(c,4,os_sc,cap_s); SAVE(c,5,ocd,create_d);
    SAVE(c,6,of,flags); SAVE(c,7,of_old,flags_j);

    JNINativeMethod d[] = {
        {"nativeCreateVirtualDisplay","(Ljava/lang/String;Z)Landroid/os/IBinder;",(void*)h_cv}
    };
    api->hookJniNativeMethods(
        e,"com/android/server/display/DisplayControl",d,N(d));
    SAVE(d,0,ocv,create_d);

    JNINativeMethod t[] = {
        {"nativeSetFlags","(JJII)V",(void*)h_ft}
    };
    api->hookJniNativeMethods(
        e,"android/view/SurfaceControl$Transaction",t,N(t));
    SAVE(t,0,oft,flags_t);

    registered = true;
}

static void pre_app(void *i,struct zygisk_app_specialize_args *a) {
    (void)i; (void)a;
    if (env) hooks(env);
}

static void pre_server(void *i,struct zygisk_server_specialize_args *a) {
    (void)i; (void)a;
    if (env) hooks(env);
}

static struct zygisk_module_abi abi = {
    .api_version = ZYGISK_API_VERSION,
    .impl = NULL,
    .preAppSpecialize = pre_app,
    .postAppSpecialize = NULL,
    .preServerSpecialize = pre_server,
    .postServerSpecialize = NULL
};

__attribute__((visibility("default")))
void zygisk_module_entry(struct zygisk_api_table *t,JNIEnv *e) {
    if (!t || !e || !t->registerModule) return;
    api = t;
    env = e;
    t->registerModule(t,&abi);
}
