// Copyright (c) 2008-2018 LG Electronics, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0


#include "debug_methods.h"
#include "subscription.h"
#include "base.h"
#include "category.h"
#include "simple_pbnjson.h"
#include "transport_priv.h"

#ifdef MALLOC_DEBUG
#include <malloc.h>
#include <dlfcn.h>
#endif
#include <pthread.h>

#include <string.h>

#ifdef SUBSCRIPTION_DEBUG
bool
_LSPrivateGetSubscriptions(LSHandle* sh, LSMessage *message, void *ctx)
{
    LSError lserror;
    LSErrorInit(&lserror);

    jvalue_ref ret_obj = NULL;
    bool json_ret = _LSSubscriptionGetJson(sh, &ret_obj, &lserror);
    if (!json_ret)
    {
        LOG_LSERROR(MSGID_LS_INVALID_JSON, &lserror);
        LSErrorFree(&lserror);
        return true;
    }

    bool reply_ret = LSMessageReply(sh, message, jvalue_tostring_simple(ret_obj), &lserror);
    if (!reply_ret)
    {
        LOG_LSERROR(MSGID_LS_SUBSEND_FAILED, &lserror);
        LSErrorFree(&lserror);
    }

    j_release(&ret_obj);

    return true;

}
#endif  /* SUBSCRIPTION_DEBUG */

#ifdef MALLOC_DEBUG
bool
_LSPrivateGetMallinfo(LSHandle* sh, LSMessage *message, void *ctx)
{
    LSError lserror;
    LSErrorInit(&lserror);

    jvalue_ref ret_obj = NULL;
    jvalue_ref true_obj = NULL;
    jvalue_ref mallinfo_obj = NULL;
    jvalue_ref allocator_name_obj = NULL;
    jvalue_ref slot_a_obj = NULL;
    jvalue_ref slot_d_obj = NULL;
    jvalue_ref slot_e_obj = NULL;
    jvalue_ref slot_f_obj = NULL;
    jvalue_ref slot_h_obj = NULL;
    jvalue_ref slot_i_obj = NULL;
    jvalue_ref slot_j_obj = NULL;

    ret_obj = jobject_create();
    if (ret_obj == NULL) goto error;

    true_obj = jboolean_create(true);
    if (true_obj == NULL) goto error;

    mallinfo_obj = jobject_create();
    if (mallinfo_obj == NULL) goto error;

    /* returnValue: true,
     * mallinfo: {key: int,...}
     */

    typedef struct mallinfo (*mallinfo_t)();
    static mallinfo_t mallinfo_p = NULL;

    if (mallinfo_p == NULL) {
        mallinfo_p = (mallinfo_t)dlsym(RTLD_DEFAULT, "mallinfo");
        if (mallinfo_p == NULL)
            mallinfo_p = (mallinfo_t)-1;
    }
    struct mallinfo mi;
    if (mallinfo_p != (mallinfo_t)-1) {
        mi = mallinfo_p();
    } else {
        memset(&mi, '\0', sizeof(mi));
    }

    allocator_name_obj = J_CSTR_TO_JVAL("ptmalloc");
    if (allocator_name_obj == NULL) goto error;

    slot_a_obj = jnumber_create_i32(mi.arena);
    if (slot_a_obj == NULL) goto error;

    slot_d_obj = jnumber_create_i32(mi.hblks);
    if (slot_d_obj == NULL) goto error;

    slot_e_obj = jnumber_create_i32(mi.hblkhd);
    if (slot_e_obj == NULL) goto error;

    slot_f_obj = jnumber_create_i32(mi.usmblks);
    if (slot_f_obj == NULL) goto error;

    slot_h_obj = jnumber_create_i32(mi.uordblks);
    if (slot_h_obj == NULL) goto error;

    slot_i_obj = jnumber_create_i32(mi.fordblks);
    if (slot_i_obj == NULL) goto error;

    slot_j_obj = jnumber_create_i32(mi.keepcost);
    if (slot_j_obj == NULL) goto error;

    jobject_put(mallinfo_obj,
                J_CSTR_TO_JVAL("allocator"),
                allocator_name_obj);
    jobject_put(mallinfo_obj,
                J_CSTR_TO_JVAL("sbrk_bytes"),
                slot_a_obj);
    jobject_put(mallinfo_obj,
                J_CSTR_TO_JVAL("mmap_count"),
                slot_d_obj);
    jobject_put(mallinfo_obj,
                J_CSTR_TO_JVAL("mmap_bytes"),
                slot_e_obj);
    jobject_put(mallinfo_obj,
                J_CSTR_TO_JVAL("max_malloc_bytes"),
                slot_f_obj);
    jobject_put(mallinfo_obj,
                J_CSTR_TO_JVAL("malloc_bytes"),
                slot_h_obj);
    jobject_put(mallinfo_obj,
                J_CSTR_TO_JVAL("slack_bytes"),
                slot_i_obj);
    jobject_put(mallinfo_obj,
                J_CSTR_TO_JVAL("trimmable_slack_bytes"),
                slot_j_obj);

    jobject_put(ret_obj,
                J_CSTR_TO_JVAL("returnValue"),
                true_obj);
    jobject_put(ret_obj, J_CSTR_TO_JVAL("mallinfo"),
                mallinfo_obj);

    bool reply_ret = LSMessageReply(sh, message, jvalue_tostring_simple(ret_obj), &lserror);
    if (!reply_ret)
    {
        LOG_LSERROR(MSGID_LS_MALLOC_SEND_FAILED, &lserror);
        LSErrorFree(&lserror);
    }

    j_release(&ret_obj);

    return true;

error:

    j_release(&ret_obj);
    j_release(&true_obj);
    j_release(&mallinfo_obj);

    j_release(&allocator_name_obj);
    j_release(&slot_a_obj);
    j_release(&slot_d_obj);
    j_release(&slot_e_obj);
    j_release(&slot_f_obj);
    j_release(&slot_h_obj);
    j_release(&slot_i_obj);
    j_release(&slot_j_obj);

    return true;
}

bool
_LSPrivateDoMallocTrim(LSHandle* sh, LSMessage *message, void *ctx)
{
    LSError lserror;
    LSErrorInit(&lserror);

    jvalue_ref ret_obj = NULL;
    jvalue_ref true_obj = NULL;
    jvalue_ref malloc_trim_obj = NULL;

    ret_obj = jobject_create();
    if (ret_obj == NULL) goto error;

    true_obj = jboolean_create(true);
    if (true_obj == NULL) goto error;


    /* returnValue: true,
     * malloc_trim: int
     */

    typedef int (*malloc_trim_t)(size_t);
    static malloc_trim_t malloc_trim_p = NULL;

    if (malloc_trim_p == NULL) {
        malloc_trim_p = (malloc_trim_t)dlsym(RTLD_DEFAULT, "malloc_trim");
        if (malloc_trim_p == NULL)
            malloc_trim_p = (malloc_trim_t)-1;
    }

    int result;
    if (malloc_trim_p != (malloc_trim_t)-1) {
        result = malloc_trim_p(0);
    } else {
        result = -1;
    }

    malloc_trim_obj = jnumber_create_i32(result);
    if (malloc_trim_obj == NULL) goto error;

    jobject_put(ret_obj,
                J_CSTR_TO_JVAL("returnValue"),
                true_obj);
    jobject_put(ret_obj,
                J_CSTR_TO_JVAL("malloc_trim"),
                malloc_trim_obj);

    bool reply_ret = LSMessageReply(sh, message, jvalue_tostring_simple(ret_obj), &lserror);
    if (!reply_ret)
    {
        LOG_LSERROR(MSGID_LS_MALLOC_TRIM_SEND_FAILED, &lserror);
        LSErrorFree(&lserror);
    }

    j_release(&ret_obj);

    return true;

error:

    j_release(&ret_obj);
    j_release(&true_obj);
    j_release(&malloc_trim_obj);

    return true;
}
#endif  /* MALLOC_DEBUG */

#ifdef INTROSPECTION_DEBUG
static void
build_categories_flat(LSHandle *sh, jvalue_ref ret_obj)
{
    GHashTableIter iter_category, iter_element;
    gpointer name_category, table_category, name_element, callback;
    struct LSCategoryTable *pTable = NULL;

    jvalue_ref category_obj = NULL;
    jvalue_ref element_obj = NULL;

    g_hash_table_iter_init(&iter_category, sh->tableHandlers);
    while (g_hash_table_iter_next(&iter_category, &name_category, &table_category))
    {
        // skip hidden method
        if (strcmp("/com/palm/luna/private", name_category) == 0)
            continue;

        pTable = (struct LSCategoryTable *)table_category;
        category_obj = jobject_get(ret_obj, j_cstr_to_buffer(name_category));
        if (!jis_valid(category_obj))
        {
            category_obj = jobject_create();
            jobject_put(ret_obj,
                        jstring_create_copy(j_cstr_to_buffer(name_category)),
                        category_obj);
        }

        // methods
        g_hash_table_iter_init(&iter_element, pTable->methods);
        while (g_hash_table_iter_next(&iter_element, &name_element, &callback))
        {
            element_obj = J_CSTR_TO_JVAL("METHOD");
            jobject_put(category_obj,
                        jstring_create_copy(j_cstr_to_buffer(name_element)),
                        element_obj);
        }

        // signals
        g_hash_table_iter_init(&iter_element, pTable->signals);
        while (g_hash_table_iter_next(&iter_element, &name_element, &callback))
        {
            element_obj = J_CSTR_TO_JVAL("SIGNAL");
            jobject_put(category_obj,
                        jstring_create_copy(j_cstr_to_buffer(name_element)),
                        element_obj);
        }
    }
}

static void
build_categories_description(LSHandle *sh, jvalue_ref categories)
{
    GHashTableIter iter_category;
    const char *category_name;
    struct LSCategoryTable *category_table;

    g_hash_table_iter_init(&iter_category, sh->tableHandlers);
    while (g_hash_table_iter_next(&iter_category, (gpointer*)&category_name, (gpointer*)&category_table))
    {
        /* skip hidden category */
        if (strcmp("/com/palm/luna/private", category_name) == 0)
            continue;

        /* Note: category information outlives our categories jobject which
         *       created only to be serialized into json right away. So no need
         *       to create a copy
         */

        jvalue_ref description = category_table->description;
        jvalue_ref methods;

        if (description == NULL)
        {
            /* ok, lets generate from scratch */
            methods = jinvalid();
        }
        else
        {
            methods = jobject_get(description, J_CSTR_TO_BUF("methods"));
            LS_ASSERT(jis_valid(methods));
        }

        jvalue_ref entry_methods = jobject_get_nested(categories, category_name, "methods", NULL);
        if (!jis_valid(entry_methods))
        {
            entry_methods = jobject_create();

            if (description == NULL)
            {
                jobject_put(categories,
                            jstring_create_nocopy(j_cstr_to_buffer(category_name)),
                            jobject_create_var(
                                jkeyval( J_CSTR_TO_JVAL("methods"), entry_methods ),
                                J_END_OBJ_DECL
                            ));
            }
            else
            {
                jvalue_ref category_entry = jvalue_shallow(description);

                (void) jobject_remove(category_entry, J_CSTR_TO_BUF("methods"));
                jobject_put(category_entry,  J_CSTR_TO_JVAL("methods"), entry_methods);

                jobject_put(categories, j_cstr_to_jval(category_name), category_entry);
            }
        }

        GHashTableIter iter_method;
        const char *method_name;
        LSMethodEntry *method_entry;

        g_hash_table_iter_init(&iter_method, category_table->methods);
        while (g_hash_table_iter_next(&iter_method, (gpointer)&method_name, (gpointer)&method_entry))
        {
            if (method_entry->function == NULL)
            {
                /* place-holder with schema for future method append (skip) */
                continue;
            }
            raw_buffer key = j_cstr_to_buffer(method_name);
            jvalue_ref method_descr;
            if (!jobject_get_exists(entry_methods, key, &method_descr))
            {
                if (jobject_get_exists(methods, key, &method_descr))
                {
                    method_descr = jvalue_shallow(method_descr);
                }
                else
                {
                    /* we'll re-use single empty object for all such entires */
                    method_descr = jobject_create();
                }
                jobject_put(entry_methods, jstring_create_nocopy(key), method_descr);
            }

            jvalue_ref provides;
            if (! jobject_get_exists(method_descr, J_CSTR_TO_BUF("provides"), &provides))
            {
                jobject_put(method_descr,
                    J_CSTR_TO_JVAL("provides"),
                    LSTransportGetGroupsFromMask(sh->transport, method_entry->security_provided_groups)
                );
            }
            else
            {
                /* There were already some provides in the array. Thus we have to merge in, filtering out the duplicates */
                jvalue_ref new_groups = LSTransportGetGroupsFromMask(sh->transport, method_entry->security_provided_groups);
                ssize_t orig_size = jarray_size(provides);
                for (ssize_t i = 0; i != jarray_size(new_groups); ++i)
                {
                    ssize_t j;
                    for (j = 0; j != orig_size; ++j)
                    {
                        if (jvalue_equal(jarray_get(provides, j), jarray_get(new_groups, i)))
                            break;
                    }
                    if (j == orig_size)
                        jarray_append(provides, jvalue_copy(jarray_get(new_groups, i)));
                }
            }
        }
    }
}

static jschema_ref introspection_params_schema;
static void init_introspection_params_schema()
{
    const char *schema_text = "{\"type\":\"object\",\"properties\":{"
        "\"type\":{\"enum\":[\"flat\",\"description\"],\"default\":\"flat\"}"
    "},\"additionalProperties\":false}";
    introspection_params_schema = jschema_parse(j_cstr_to_buffer(schema_text), JSCHEMA_DOM_NOOPT, NULL);
}
static jschema_ref get_introspection_params_schema()
{
    static pthread_once_t initialized = PTHREAD_ONCE_INIT;
    (void) pthread_once(&initialized, init_introspection_params_schema);
    return introspection_params_schema;
}

bool
_LSPrivateInrospection(LSHandle* sh, LSMessage *message, void *ctx)
{
    jvalue_ref reply;
    jerror *error = NULL;
    jvalue_ref params =
            jdom_create(j_cstr_to_buffer(LSMessageGetPayload(message)), get_introspection_params_schema(), &error);

    if (!jis_valid(params))
    {
        char buffer[256];
        jerror_to_string(error, buffer, sizeof(buffer));

        reply = jobject_create_var(
            jkeyval( J_CSTR_TO_JVAL("returnValue"), jboolean_create(false) ),
            jkeyval( J_CSTR_TO_JVAL("errorText"), jstring_create(buffer) ),
            J_END_OBJ_DECL
        );

        jerror_free(error);
    }
    else if (jstr_eq_cstr(jobject_get(params, J_CSTR_TO_BUF("type")), "description"))
    {
        jvalue_ref categories = jobject_create();
        build_categories_description(sh, categories);

        /* If the request came from through a private (universal) handle,
         * we should also check the public handle, and combine results
         * from both of the handles
         */
        if (sh == sh->transport->back_sh[false])
        {
            LSHandle *pub_handle = sh->transport->back_sh[true];
            if (pub_handle)
                build_categories_description(pub_handle, categories);
        }

        reply = jobject_create_var(
            jkeyval( J_CSTR_TO_JVAL("returnValue"), jboolean_create(true) ),
            jkeyval( J_CSTR_TO_JVAL("categories"), categories),
            J_END_OBJ_DECL
        );
    }
    else
    {
        /* FIXME: for compatibility reasons this were kept as-is (without
         *        supplying answer with returnValue indicator)
         */
        reply = jobject_create();
        build_categories_flat(sh, reply);

        /* If the request came from through a private (universal) handle,
         * we should also check the public handle, and combine results
         * from both of the handles
         */
        if (sh == sh->transport->back_sh[false])
        {
            LSHandle *pub_handle = sh->transport->back_sh[true];
            if (pub_handle)
                build_categories_flat(pub_handle, reply);
        }
    }

    LSError lserror;
    LSErrorInit(&lserror);

    bool reply_ret = LSMessageReply(sh, message, jvalue_tostring_simple(reply), &lserror);
    if (!reply_ret)
    {
        LOG_LSERROR(MSGID_LS_INTROS_SEND_FAILED, &lserror);
        LSErrorFree(&lserror);
    }
    j_release(&reply);

    return reply_ret; /* false if unable to reply */
}
#endif  /* INTROSPECTION_DEBUG */
