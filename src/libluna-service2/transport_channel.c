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

#include "transport_channel.h"

#include "error.h"
#include "transport.h"
#include "transport_utils.h"
#include "transport_client.h"


/**
 *******************************************************************************
 * @brief Add a watch to a channel and attach it to the main context.
 *
 * @param  channel       IN  channel to watch
 * @param  condition     IN  condition to watch
 * @param  context       IN  main context
 * @param  transport_cb  IN  callback when watch is triggered
 * @param  user_data     IN  context passed to callback
 * @param  destroy_cb    IN  callback when watch is destroyed
 * @param  out_watch     OUT newly created watch
 *******************************************************************************
 */
static void
AddWatch(_LSTransportChannel *channel, GIOCondition condition, GMainContext *context,
         GIOFunc transport_cb, void *user_data, GDestroyNotify destroy_cb, GSource **out_watch)
{
    LS_ASSERT(channel != NULL);
    LS_ASSERT(channel->channel != NULL);
    LS_ASSERT(context != NULL);
    LS_ASSERT(out_watch != NULL);
    LS_ASSERT(*out_watch == NULL);

    GSource *watch = g_io_create_watch(channel->channel, condition);

    if (channel->priority != G_PRIORITY_DEFAULT)
    {
        g_source_set_priority(watch, channel->priority);
    }

    g_source_set_callback(watch, (GSourceFunc)transport_cb, user_data, destroy_cb);

    /* we set this before attaching because once we call attach, we can potentially
     * wake a separate thread running the mainloop associated with this context */
    *out_watch = watch;

    g_source_set_can_recurse(watch, true);
    g_source_attach(watch, context);
}

/**
 *******************************************************************************
 * @brief Remove a watch from a channel.
 *
 * @param  channel      IN      channel that watch is on
 * @param  out_watch    IN/OUT  watch (set to NULL after destroying)
 *******************************************************************************
 */
static void
RemoveWatch(_LSTransportChannel *channel, GSource **out_watch)
{
    LS_ASSERT(channel != NULL);
    LS_ASSERT(out_watch != NULL);
    LS_ASSERT(*out_watch != NULL);

    /* The user_data will be cleaned up by the GDestroyNotify callback */
    g_source_destroy(*out_watch);
    g_source_unref(*out_watch);
    *out_watch = NULL;
}


/**
 * @cond INTERNAL
 * @defgroup LunaServiceTransportChannel Transport channel
 * @ingroup LunaServiceTransport
 * @{
 */

/**
 *******************************************************************************
 * @brief Initialize a channel.
 *
 * @param  channel      IN  channel to initialize
 * @param  fd           IN  fd
 * @param  priority     IN  priority
 *
 * @retval true on success
 * @retval false on failure
 *******************************************************************************
 */
bool
_LSTransportChannelInit(_LSTransportChannel *channel, int fd, int priority)
{
    LS_ASSERT(channel != NULL);

    channel->fd = fd;
    channel->priority = priority;
    channel->channel = g_io_channel_unix_new(fd);
    channel->send_watch = NULL;
    channel->recv_watch = NULL;
    channel->accept_watch = NULL;

    if (pthread_mutex_init(&channel->send_watch_lock, NULL))
    {
        LOG_LS_ERROR(MSGID_LS_MUTEX_ERR, 0, "Could not initialize mutex");
        return false;
    }

    return true;
}

/**
 *******************************************************************************
 * @brief Deinitialize a channel.
 *
 * @param  channel  IN channel
 *******************************************************************************
 */
void
_LSTransportChannelDeinit(_LSTransportChannel *channel)
{
    LS_ASSERT(channel != NULL);

    if (channel->send_watch)
    {
        _LSTransportChannelRemoveSendWatch(channel);
    }

    if (channel->recv_watch)
    {
        _LSTransportChannelRemoveReceiveWatch(channel);
    }

    if (channel->accept_watch)
    {
        _LSTransportChannelRemoveAcceptWatch(channel);
    }

    if (channel->channel)
    {
        g_io_channel_unref(channel->channel);
        channel->channel = NULL;
    }

    if (pthread_mutex_destroy(&channel->send_watch_lock))
        LOG_LS_WARNING(MSGID_LS_MUTEX_ERR, 0, "Could not destroy mutex &channel->send_watch_lock");
}

/**
 *******************************************************************************
 * @brief Get the underlying file descriptor for a channel (not ref counted).
 *
 * @param  channel  IN  channel
 *
 * @retval  fd
 *******************************************************************************
 */
inline int
_LSTransportChannelGetFd(const _LSTransportChannel *channel)
{
    return channel->fd;
}

/**
 *******************************************************************************
 * @brief Close a channel.
 *
 * @param  channel  IN  channel
 * @param  flush    IN  flush the channel before closing
 *******************************************************************************
 */
void
_LSTransportChannelClose(_LSTransportChannel *channel, bool flush)
{
    LS_ASSERT(channel != NULL);

    GError *err = NULL;

    if (channel->channel)
    {
        G_GNUC_UNUSED GIOStatus status = g_io_channel_shutdown(channel->channel, flush, &err);

        if (err != NULL)
        {
            LOG_LS_WARNING(MSGID_LS_CHANNEL_ERR, 2,
                           PMLOGKFV("ERROR_CODE", "%d", err->code),
                           PMLOGKS("ERROR", err->message),
                           "Error on channel close (status: %d): %s", status, err->message);
            g_error_free(err);
        }

        g_io_channel_unref(channel->channel);
        channel->channel = NULL;
    }
}

/**
 *******************************************************************************
 * @brief Set the priority on a channel.
 *
 * @param  channel  IN  channel
 * @param  priority IN  priority
 *******************************************************************************
 */
void
_LSTransportChannelSetPriority(_LSTransportChannel *channel, int priority)
{
    LS_ASSERT(channel != NULL);

    if (channel->send_watch)
    {
        g_source_set_priority(channel->send_watch, priority);
    }

    if (channel->recv_watch)
    {
        g_source_set_priority(channel->recv_watch, priority);
    }

    channel->priority = priority;
}


/**
 *******************************************************************************
 * @brief Add a send watch to a channel.
 *
 * @param  channel  IN  channel
 * @param  context  IN  main loop context
 * @param  client   IN  client to pass to watch callback
 *******************************************************************************
 */
void
_LSTransportChannelAddSendWatch(_LSTransportChannel *channel, GMainContext *context, _LSTransportClient *client)
{
    LS_ASSERT(channel != NULL);
    LS_ASSERT(context != NULL);

    if (!channel->send_watch)
    {
        SEND_WATCH_LOCK(&channel->send_watch_lock);

        if (!channel->send_watch)
        {
            LOG_LS_DEBUG("%s: channel: %p, context: %p, client: %p\n", __func__, channel, context, client);

            _LSTransportClientRef(client);
            AddWatch(channel, G_IO_OUT, context, _LSTransportSendClient, client, (GDestroyNotify) _LSTransportClientUnref, &channel->send_watch);
        }

        SEND_WATCH_UNLOCK(&channel->send_watch_lock);
    }
}

/**
 *******************************************************************************
 * @brief Remove a send watch from a channel.
 *
 * @param  channel  IN  channel
 *******************************************************************************
 */
void
_LSTransportChannelRemoveSendWatch(_LSTransportChannel *channel)
{
    LS_ASSERT(channel != NULL);

    LOG_LS_DEBUG("%s: channel: %p\n", __func__, channel);

    if (channel->send_watch)
    {
        SEND_WATCH_LOCK(&channel->send_watch_lock);
        RemoveWatch(channel, &channel->send_watch);
        SEND_WATCH_UNLOCK(&channel->send_watch_lock);
        /* client is unref'd by GDestroyNotify callback */
    }
}

/**
 *******************************************************************************
 * @brief Add a receive watch to a channel.
 *
 * @param  channel  IN  channel
 * @param  context  IN  main loop context
 * @param  client   IN  client to pass to watch callback
 *******************************************************************************
 */
void
_LSTransportChannelAddReceiveWatch(_LSTransportChannel *channel, GMainContext *context, _LSTransportClient *client)
{
    LS_ASSERT(channel != NULL);
    LS_ASSERT(context != NULL);

    if (!channel->recv_watch)
    {
        LOG_LS_DEBUG("%s: channel: %p, context: %p, client: %p\n", __func__, channel, context, client);

        _LSTransportClientRef(client);
        AddWatch(channel, G_IO_IN | G_IO_ERR | G_IO_HUP, context,
                 _LSTransportReceiveClient, client, (GDestroyNotify) _LSTransportClientUnref, &channel->recv_watch);
    }
}

/**
 *******************************************************************************
 * @brief Remove a receive watch from a channel.
 *
 * @param  channel  IN  channel
 *******************************************************************************
 */
void
_LSTransportChannelRemoveReceiveWatch(_LSTransportChannel *channel)
{
    LS_ASSERT(channel != NULL);
    LS_ASSERT(channel->recv_watch != NULL);

    LOG_LS_DEBUG("%s: channel: %p\n", __func__, channel);

    if (channel->recv_watch)
    {
        RemoveWatch(channel, &channel->recv_watch);
        /* client is unref'd by GDestroyNotify callback */
    }
}

/**
 *******************************************************************************
 * @brief Add an accept watch to a channel.
 *
 * @param  channel  IN  channel
 * @param  context  IN  main loop context
 * @param  user_data IN user data to pass to watch callback
 *******************************************************************************
 */
void
_LSTransportChannelAddAcceptWatch(_LSTransportChannel *channel, GMainContext *context, void *user_data)
{
    LS_ASSERT(channel != NULL);
    LS_ASSERT(context != NULL);

    LOG_LS_DEBUG("%s: channel: %p, context: %p, transport: %p\n", __func__, channel, context, user_data);

    AddWatch(channel, G_IO_IN | G_IO_ERR | G_IO_HUP, context,
             _LSTransportAcceptConnection, user_data, NULL, &channel->accept_watch);
}

/**
 *******************************************************************************
 * @brief Remove an accept watch from a channel.
 *
 * @param  channel  IN  channel
 *******************************************************************************
 */
void
_LSTransportChannelRemoveAcceptWatch(_LSTransportChannel *channel)
{
    LS_ASSERT(channel != NULL);
    LS_ASSERT(channel->accept_watch != NULL);

    LOG_LS_DEBUG("%s: channel: %p\n", __func__, channel);

    RemoveWatch(channel, &channel->accept_watch);
}

bool
_LSTransportChannelHasReceiveWatch(const _LSTransportChannel *channel)
{
    LS_ASSERT(channel != NULL);
    return (channel->recv_watch != NULL);
}

bool
_LSTransportChannelHasSendWatch(const _LSTransportChannel *channel)
{
    LS_ASSERT(channel != NULL);
    return (channel->send_watch != NULL);
}

/**
 *******************************************************************************
 * @brief Set the given channel to blocking read/write mode. If
 * prev_state_blocking is not NULL, the previous state will be saved in that
 * variable.
 *
 * @param  channel                  IN  channel
 * @param  prev_state_blocking      OUT true if channel was set to block
 *                                      before calling this function,
 *                                      otherwise false
 *******************************************************************************
 */
void
_LSTransportChannelSetBlock(_LSTransportChannel *channel, bool *prev_state_blocking)
{
    LS_ASSERT(channel != NULL);
    int fd = _LSTransportChannelGetFd(channel);
    _LSTransportFdSetBlock(fd, prev_state_blocking);
}

/**
 *******************************************************************************
 * @brief Set the given channel to non-blocking read/write mode. If
 * prev_state_blocking is not NULL, the previous state will be saved in that
 * variable.
 *
 * @param  channel                  IN  channel
 * @param  prev_state_blocking      OUT true if channel was set to block
 *                                      before calling this function,
 *                                      otherwise false
 *******************************************************************************
 */
void
_LSTransportChannelSetNonblock(_LSTransportChannel *channel, bool *prev_state_blocking)
{
    LS_ASSERT(channel != NULL);
    int fd = _LSTransportChannelGetFd(channel);
    _LSTransportFdSetNonBlock(fd, prev_state_blocking);
}

/**
 *******************************************************************************
 * @brief Restore the saved blocking state to a channel (from
 * _LSTransportChannelSetBlock or _LSTransportChannelSetNonblock).
 *
 * @param  channel              IN  channel
 * @param  prev_state_blocking  IN  true sets channel to blocking, otherwise
 *                                  channel is set to non-blocking
 *******************************************************************************
 */
void
_LSTransportChannelRestoreBlockState(_LSTransportChannel *channel, const bool *prev_state_blocking)
{
    LS_ASSERT(channel != NULL);
    LS_ASSERT(prev_state_blocking != NULL);

    if (*prev_state_blocking)
    {
        _LSTransportChannelSetBlock(channel, NULL);
    }
    else
    {
        _LSTransportChannelSetNonblock(channel, NULL);
    }
}

/**
 * @} END OF LunaServiceTransportChannel
 * @endcond
 */
