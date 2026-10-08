#include <string.h>
#include "zygisk.h"

#define PHOTOS "com.google.android.apps.photos"

static JNIEnv *env;
static struct zygisk_api_table *api;
static bool inject;

static void set_string(jclass build, const char *field, const char *value) {
    jfieldID id = (*env)->GetStaticFieldID(env, build, field, "Ljava/lang/String;");
    if (id) {
        jstring str = (*env)->NewStringUTF(env, value);
        if (str) {
            (*env)->SetStaticObjectField(env, build, id, str);
            (*env)->DeleteLocalRef(env, str);
        }
    }
    (*env)->ExceptionClear(env);
}

static void pre(void *impl, struct zygisk_app_specialize_args *args) {
    (void)impl;
    inject = false;

    if (args && args->nice_name && *args->nice_name) {
        const char *name = (*env)->GetStringUTFChars(env, *args->nice_name, NULL);
        if (name) {
            inject = strcmp(name, PHOTOS) == 0;
            (*env)->ReleaseStringUTFChars(env, *args->nice_name, name);
        }
    }

    if (!inject)
        api->setOption(api->impl, ZYGISK_DLCLOSE_MODULE_LIBRARY);
}

static void post(void *impl, const struct zygisk_app_specialize_args *args) {
    (void)impl;
    (void)args;
    if (!inject)
        return;

    jclass build = (*env)->FindClass(env, "android/os/Build");
    if (!build) {
        (*env)->ExceptionClear(env);
        return;
    }

    set_string(build, "BRAND", "google");
    set_string(build, "MANUFACTURER", "Google");
    set_string(build, "MODEL", "Pixel XL");
    set_string(build, "FINGERPRINT",
               "google/marlin/marlin:10/QP1A.191005.007.A3/5972272:user/release-keys");

    (*env)->DeleteLocalRef(env, build);
}

static struct zygisk_module_abi abi = {
    .api_version = ZYGISK_API_VERSION,
    .preAppSpecialize = pre,
    .postAppSpecialize = post,
};

__attribute__((visibility("default")))
void zygisk_module_entry(struct zygisk_api_table *table, JNIEnv *e) {
    if (table && e) {
        api = table;
        env = e;
        table->registerModule(table, &abi);
    }
}
