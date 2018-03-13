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

#include <glib.h>

#include <stdbool.h>
#include <string.h>
#include <pthread.h>
#include <errno.h>
#include <unistd.h>

#include <luna-service2/lunaservice.h>

#include "base.h"
#include "message.h"
#include "transport_priv.h"

/**
 * @addtogroup LunaServiceMainloop
 *
 * @{
 */

/**
 *******************************************************************************
 * @brief Get a glib mainloop context for service
 *
 * @param sh      IN  handle to service
 * @param lserror OUT set on error
 *
 * @retval GMainContext, glib mainloop context
 *******************************************************************************
 */
GMainContext * LSGmainGetContext(LSHandle *sh, LSError *lserror)
{
    _LSErrorIfFail(sh != NULL, lserror, MSGID_LS_INVALID_HANDLE);
    LSHANDLE_VALIDATE(sh);

    return sh->context;
}

/**
 *******************************************************************************
 * @brief Attach a service to a glib mainloop
 *
 * @param sh          IN handle to service
 * @param mainContext IN context
 * @param lserror     OUT set on error
 *
 * @return true on success, otherwise false
 *******************************************************************************
 */
bool LSGmainContextAttach(LSHandle *sh, GMainContext *mainContext, LSError *lserror)
{
    _LSErrorIfFail(sh != NULL, lserror, MSGID_LS_INVALID_HANDLE);
    LSHANDLE_VALIDATE(sh);

    _LSErrorIfFailMsg(mainContext != NULL, lserror, MSGID_LS_MAINCONTEXT_ERROR, -1,
                   "%s: %s", __FUNCTION__, ": No maincontext.");

    _LSErrorGotoIfFail(error,
            !sh->transport->mainloop_context || mainContext == sh->transport->mainloop_context,
            lserror,
            MSGID_LS_PALM_SERVICE_WITH_TWO_CONTEXTS,
            -1);

    if(!sh->transport->mainloop_context)
        _LSTransportGmainAttach(sh->transport, mainContext);
    sh->context = g_main_context_ref(mainContext);

    return true;

error:
    return false;
}

/**
 *******************************************************************************
 * @brief Attach a service to a glib mainloop.
 *
 * @param  sh        IN  handle to service
 * @param  mainLoop  IN  loop to attach
 * @param  lserror   OUT set on error
 *
 * @return true on success, otherwise false
 *******************************************************************************
 */
bool
LSGmainAttach(LSHandle *sh, GMainLoop *mainLoop, LSError *lserror)
{
    _LSErrorIfFail(mainLoop != NULL, lserror, MSGID_LS_MAINLOOP_ERROR);
    GMainContext *context = g_main_loop_get_context(mainLoop);
    return LSGmainContextAttach(sh, context, lserror);
}

/**
 * @deprecated Avoid using LSPalmService, use LSHandle instead.
 */
bool LSGmainContextAttachPalmService(LSPalmService *psh, GMainContext *mainContext, LSError *lserror)
{
    _LSErrorIfFail(psh != NULL, lserror, MSGID_LS_INVALID_HANDLE);
    _LSErrorIfFail(mainContext != NULL, lserror, MSGID_LS_MAINCONTEXT_ERROR);

    bool retVal = LSGmainContextAttach(psh->private_sh, mainContext, lserror);
    if (retVal)
        psh->public_sh->context = g_main_context_ref(mainContext);

    return retVal;
}

/**
 * @deprecated Avoid using LSPalmService, use LSHandle instead.
 */
bool
LSGmainAttachPalmService(LSPalmService *psh, GMainLoop *mainLoop, LSError *lserror)
{
    _LSErrorIfFail(mainLoop != NULL, lserror, MSGID_LS_MAINLOOP_ERROR);
    GMainContext *context = g_main_loop_get_context(mainLoop);
    return LSGmainContextAttachPalmService(psh, context, lserror);
}

/**
 *******************************************************************************
 * @brief Detach a service from a glib mainloop. You should NEVER use this
 * function unless you are fork()'ing without exec()'ing and know what you are
 * doing. This will perform nearly all the same cleanup as LSUnregister(), with
 * the exception that it will not send out shutdown messages or flush any
 * buffers. It is intended to be used only when fork()'ing so that your child
 * process can continue without interfering with the parent's file descriptors,
 * since open file descriptors are duplicated during a fork().
 *
 * @param  sh      IN  handle to service
 * @param  lserror OUT set on error
 *
 * @return true on success, otherwise false
 *******************************************************************************
 */
bool
LSGmainDetach(LSHandle *sh, LSError *lserror)
{
    _LSErrorIfFail(sh != NULL, lserror, MSGID_LS_INVALID_HANDLE);
    _LSErrorIfFailMsg(sh->context != NULL, lserror, MSGID_LS_MAINCONTEXT_ERROR, -1,
                      "%s: %s", __FUNCTION__, ": No maincontext.");

    /* We "unregister" without actually flushing or sending shutdown messages */
    return _LSUnregisterCommon(sh, false, LSHANDLE_GET_RETURN_ADDR(), lserror);
}

/**
 *******************************************************************************
 * @brief @see LSGmainDetach(). This is the equivalent for a "PalmService"
 * handle.
 *
 * @param  psh      IN  PalmService handle
 * @param  lserror  OUT set on error
 *
 * @return true on success, otherwise false
 *******************************************************************************
 */
bool
LSGmainDetachPalmService(LSPalmService *psh, LSError *lserror)
{
    bool retVal;

    retVal = LSGmainDetach(psh->public_sh, lserror);
    if (!retVal) return retVal;
    retVal = LSGmainDetach(psh->private_sh, lserror);
    if (!retVal) return retVal;

    return retVal;
}

/**
 *******************************************************************************
 * @brief Sets the priority level on the associated GSources for
 *        the service connection.
 *
 *        This should be called after @ref LSGmainAttach().
 *
 *        See glib documentation for GSource priority levels.
 *
 * @param sh       IN  handle to service
 * @param priority IN  priority level
 * @param lserror  OUT set on error
 *
 * @return true on success, otherwise false
 *******************************************************************************
 */
bool
LSGmainSetPriority(LSHandle *sh, int priority, LSError *lserror)
{
    _LSErrorIfFail(sh != NULL, lserror, MSGID_LS_INVALID_HANDLE);

    LSHANDLE_VALIDATE(sh);

    return _LSTransportGmainSetPriority(sh->transport, priority, lserror);
}

/**
 * @deprecated Avoid using LSPalmService, use LSHandle instead.
 */
bool
LSGmainSetPriorityPalmService(LSPalmService *psh, int priority, LSError *lserror)
{
    bool retVal;
    _LSErrorIfFail(psh != NULL, lserror, MSGID_LS_INVALID_HANDLE);

    if (psh->public_sh)
    {
        retVal = LSGmainSetPriority(psh->public_sh, priority, lserror);
        if (!retVal) return false;
    }
    if (psh->private_sh)
    {
        retVal = LSGmainSetPriority(psh->private_sh, priority, lserror);
        if (!retVal) return false;
    }
    return true;
}

/** @} END OF LunaServiceMainloop */
