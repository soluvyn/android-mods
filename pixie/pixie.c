#include <jni.h>
#include <stdbool.h>
#include <string.h>

#include "zygisk.h"

#define PHOTOS_PACKAGE "com.google.android.apps.photos"

static JNIEnv *g_env;
static struct zygisk_api_table *g_api;
static bool g_should_inject;

static void set_static_string(JNIEnv *env, jclass clazz,
                              const char *field, const char *value) {
    jfieldID id = (*env)->GetStaticFieldID(
        env, clazz, field, "Ljava/lang/String;"
    );

    if (id == NULL) {
        (*env)->ExceptionClear(env);
        return;
    }

    jstring str = (*env)->NewStringUTF(env, value);
    if (str == NULL) {
        (*env)->ExceptionClear(env);
        return;
    }

    (*env)->SetStaticObjectField(env, clazz, id, str);
    (*env)->ExceptionClear(env);
    (*env)->DeleteLocalRef(env, str);
}

static void preAppSpecialize(void *impl,
                             struct zygisk_app_specialize_args *args) {
    (void)impl;

    g_should_inject = false;

    if (args == NULL || args->nice_name == NULL || *(args->nice_name) == NULL)
        return;

    jstring name = *(args->nice_name);
    const char *process = (*g_env)->GetStringUTFChars(g_env, name, NULL);

    if (process == NULL)
        return;

    g_should_inject = strcmp(process, PHOTOS_PACKAGE) == 0;

    (*g_env)->ReleaseStringUTFChars(g_env, name, process);

    if (g_api != NULL && g_api->setOption != NULL)
        g_api->setOption(g_api->impl, ZYGISK_DLCLOSE_MODULE_LIBRARY);
}

static void postAppSpecialize(
    void *impl,
    const struct zygisk_app_specialize_args *args) {
    (void)impl;
    (void)args;

    if (!g_should_inject || g_env == NULL)
        return;

    jclass build = (*g_env)->FindClass(g_env, "android/os/Build");
    if (build == NULL) {
        (*g_env)->ExceptionClear(g_env);
        return;
    }

    set_static_string(g_env, build, "BRAND", "google");
    set_static_string(g_env, build, "MANUFACTURER", "Google");
    set_static_string(g_env, build, "MODEL", "Pixel XL");
    set_static_string(
        g_env,
        build,
        "FINGERPRINT",
        "google/marlin/marlin:10/QP1A.191005.007.A3/5972272:user/release-keys"
    );

    (*g_env)->DeleteLocalRef(g_env, build);
}

static struct zygisk_module_abi g_abi = {
    .api_version = ZYGISK_API_VERSION,
    .impl = NULL,
    .preAppSpecialize = preAppSpecialize,
    .postAppSpecialize = postAppSpecialize,
    .preServerSpecialize = NULL,
    .postServerSpecialize = NULL
};

__attribute__((visibility("default")))
void zygisk_module_entry(struct zygisk_api_table *table, JNIEnv *env) {
    if (table == NULL || env == NULL)
        return;

    g_api = table;
    g_env = env;

    table->registerModule(table, &g_abi);
}
