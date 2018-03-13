// Copyright (c) 2014-2018 LG Electronics, Inc.
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

#pragma once

#include <luna-service2/lunaservice.h>
#include <luna-service2/lunaservice-meta.h>
#include "call.hpp"
#include "server_status.hpp"

#include <cstring>
#include <iostream>
#include <memory>
#include <cstddef>

namespace LS {

#define GET_MACRO_FUNCTION(_1,_2,NAME,...) NAME

// CATEGORY BEGIN
#define LS_CATEGORY_BEGIN2(cl, name)                    \
    { static_assert(std::is_base_of<cl, std::remove_pointer<decltype(this)>::type>::value, \
                   "Class must be a parent of this");   \
      typedef cl cl_t;                                  \
      const char *category_name = name;                 \
      constexpr static const LSMethod table[] = {

#define LS_CATEGORY_BEGIN1(name)                        \
    LS_CATEGORY_BEGIN2(std::remove_pointer<decltype(this)>::type, name)

#define LS_CATEGORY_BEGIN(...)                          \
    GET_MACRO_FUNCTION(__VA_ARGS__, LS_CATEGORY_BEGIN2, LS_CATEGORY_BEGIN1)(__VA_ARGS__)

// CATEGORY METHOD
#define LS_CATEGORY_METHOD2(name,flags) { #name,        \
      &LS::Handle::methodWraper<cl_t, &cl_t::name>,     \
      static_cast<LSMethodFlags>(flags) },

#define LS_CATEGORY_METHOD1(name) LS_CATEGORY_METHOD2(name, LUNA_METHOD_FLAGS_NONE)

#define LS_CATEGORY_METHOD(...)                         \
    GET_MACRO_FUNCTION(__VA_ARGS__,LS_CATEGORY_METHOD2,LS_CATEGORY_METHOD1)(__VA_ARGS__)

// CATEGORY END
#define LS_CATEGORY_END {nullptr, nullptr}};            \
    registerCategory(category_name, table, nullptr, nullptr); \
    setCategoryData(category_name, this); \
    }

/**
 * @mainpage LunaService2++
 * @section INTRO Intro
 * The Luna Service (LS) is a bus-based Interprocess Communication (IPC) mechanism for components in webOS.
 * The Luna Service is composed of a client library and of a central hub daemon.
 * The client library provides API support to register on the bus and communicate with other components.
 * The hub provides a central clearing house for all communication. Utilities for monitoring and debugging the bus are included.
 * After having registered on the Luna Service Bus, services and applications can call public methods of other services and applications registered on the Luna Service Bus.
 * The Luna Service API offers the mechanism that enables sending and receiving data within a single device.
 * Both third-party and internal services can use Luna Service Bus. The operations that a service can perform on the Luna Service Bus are limited by the assigned security permissions.
 */

/**
 * @ingroup LunaServicePP
 * @brief Bus end-point base class
 * It provides an API to control service and client end-points of luna hub.
 * You can inherit or use it to create your own service. However this class has not been designed to be used as a precise low-level full functional wrapper for the API.
 * Instead additional Service and Client wrappers could be created for easy use of the functionality.
 */
class Handle
{
    friend Handle registerService(const char *, bool);
    friend Handle registerApplicationService(const char *, const char *);

public:
    /**
     * @brief Map a category method to some class method.
     * It allows to obtain LSMethod presentation of a given method.
     * This is used to create a Category method list.
     *
     * @note An object address which has the method should be passed as user_data parameter to setCategoryData method.
     *       This mean all methods of a category should be methods of one class as for now.
     *
     * @tparam ClassT class of category
     * @tparam MethT method of the class ClassT
     */
    template<typename ClassT, bool (ClassT::*MethT)(LSMessage&)>
    static bool methodWraper(LSHandle *h, LSMessage *m, void *ctx)
    {
        auto this_ = static_cast<ClassT*>(ctx);
        return (this_->*MethT)(*m);
    }

    /**
     * Does nothing. Only an empty inactive instance is created.
     * This handle is not registered.
     */
    Handle()
        : _handle(nullptr)
    { }


    Handle(const Handle &) = delete;
    Handle &operator=(const Handle &) = delete;

    Handle(Handle &&other) noexcept
        : _handle(other.release())
    { }


    /**
     * Registers a new service with the specified name.
     * @param name the service name
     */
    Handle(const char *name)
    {
        Error error;

        if (!LSRegister(name, &_handle, error.get()))
            throw error;
    }

    /**
     * Registers a new anonymous service.
     *
     * @param name the service name, which equals to NULL
     * @deprecated anonymous services are deprecated, you must define a name for you client
     */
    Handle(std::nullptr_t name) LS_DEPRECATED_PUBPRIV;

    /**
     * Registers a new service with the specified name.
     * @param name the service name
     * @param public_service true if we need the service to be public
     * @deprecated Avoid specification of public/private hub
     */
    Handle(const char *name, bool public_service) LS_DEPRECATED_PUBPRIV;

    /**
     * Registers a new service with a specified name and an application Id.
     * @param name the service name
     * @param app_id additional application identifier, which can be used to distinguish
     * applications, that work within one registration(HANDLE) on the bus.
     * The recipient should be prepared to query app_from an incoming message.
     */
    Handle(const char *name, const char *app_id)
    {
        Error error;

        if (!LSRegisterApplicationService(name, app_id, &_handle, error.get()))
            throw error;

    }

    Handle &operator=(Handle &&other)
    {
        if (_handle)
        {
            Error error;

            if (!LSUnregister(_handle, error.get()))
                throw error;
        }
        _handle = other.release();
        return *this;
    }

    ~Handle()
    {
        if (_handle)
        {
            Error error;

            if (!LSUnregister(_handle, error.get()))
                error.logError("LS_FAILED_TO_UNREG");
        }
    }

    /**
     * Get handle to service
     *
     * @return service handle for libluna-service c API
     */
    LSHandle *get() { return _handle; }

    /**
     * Get handle to service
     *
     * @return service handle for libluna-service c API
     */
    const LSHandle *get() const { return _handle; }

    /**
     * Get a LSHandle name.
     *
     * @return service name
     */
    const char *getName() const
    { return LSHandleGetName(_handle); }

    /**
     * Check if the end-point registration was successfully performed
     */
    explicit operator bool() const { return _handle; }

    /**
     * Register tables of callbacks associated with the message category.
     *
     * @param category   category name starting from '/'
     * @param methods    c API style method describing structure objects
     * @param ls_signals table of signals
     * @param properties table of properties.
     */
    void registerCategory(const char       *category,
                          const LSMethod   *methods,
                          const LSSignal   *ls_signals,
                          const LSProperty *properties)
    {
        Error error;
        if (!LSRegisterCategory(_handle,
                                category,
                                const_cast<LSMethod *>(methods),
                                const_cast<LSSignal *>(ls_signals),
                                const_cast<LSProperty *>(properties),
                                error.get()))
        {
            throw error;
        }
    }

    /**
     * Append methods to the category.
     * Creates a category if needed.
     *
     * @param category   name of category of this end-point
     * @param methods    c-style method list. Should end with zeroed item
     * @param ls_signals c-style signal list. Should end with zeroed item
     */
    void registerCategoryAppend(const char *category,
                                LSMethod   *methods,
                                LSSignal   *ls_signals)
    {
        Error error;

        if (!LSRegisterCategoryAppend(_handle, category, methods, ls_signals, error.get()))
            throw error;
    }

    /**
     * Set a function to be called if we are disconnected from the bus.
     *
     * @param disconnect_handler function callback
     * @param user_data user data to be passed to callback
     */
    void setDisconnectHandler(LSDisconnectHandler disconnect_handler, void *user_data)
    {
        Error error;

        if (!LSSetDisconnectHandler(_handle, disconnect_handler, user_data, error.get()))
            throw error;
    }

    /**
     * @brief Set the userdata that is delivered to each callback registered
     *        to the category.
     *
     * @param category category name
     * @param user_data user data to set
     *
     * @note If method user data is set using @ref setMethodData, it overrides
     * category data
     */
    void setCategoryData(const char *category, void *user_data)
    {
        Error error;

        if (!LSCategorySetData(_handle, category, user_data, error.get()))
            throw error;
    }

    /**
     * @brief Specify meta information about category
     *
     * Set JSON value that describes specified category. Provides validation schema
     * for input params and replies. Gives some description for calls etc.
     *
     * @param category    identifier of category this information provided for
     * @param description information itself (no ownership transfer)
     *                    see / category in example"
     */
    void setCategoryDescription(const char *category, jvalue_ref description)
    {
        Error error;

        if (!LSCategorySetDescription(_handle, category, description, error.get()))
            throw error;
    }

    /**
     * @brief Set the userdata that is delivered to callback registered
     *        to the method. Overrides category data as callback context.
     *
     * @param category category name
     * @param method method name
     * @param user_data user data to set
     *
     * @note It's recommended to set method user data before method registration,
     *       otherwise, if mainloop is running, there is a chance to get callback
     *       called with category data.
     */
    void setMethodData(const char *category, const char *method, void *user_data)
    {
        Error error;

        if (!LSMethodSetData(_handle, category, method, user_data, error.get()))
            throw error;
    }

    /**
     * @brief Push a role file for this process. Once the role file has been
     * pushed with this function, the process will be restricted to the
     * constraints of the provided role file.
     *
     * @param role_path full path to role file
     */
    void pushRole(const char *role_path)
    {
        Error error;

        if (!LSPushRole(_handle, role_path, error.get()))
            throw error;
    }

    /**
     * Attach service to a glib mainloop context.
     *
     * @param context context to the glib main loop
     */
    void attachToLoop(GMainContext *context) const
    {
        Error error;

        if (!LSGmainContextAttach(_handle, context, error.get()))
            throw error;
    }

    /**
     * Attach a service to a glib main loop
     *
     * @param loop loop to attach
     */
    void attachToLoop(GMainLoop *loop) const
    {
        Error error;

        if (!LSGmainAttach(_handle, loop, error.get()))
            throw error;
    }

    /**
     * @brief Detach the end-point from a glib mainloop.
     * You should NEVER use this function unless you are fork()'ing without exec()'ing
     * and know what you are doing.
     * This will perform nearly all the same cleanup as LSUnregister(), with
     * the exception that it will not send out shutdown messages or flush any
     * buffers. It is intended to be used only when fork()'ing so that your child
     * process can continue without interfering with the parent's file descriptors,
     * since open file descriptors are duplicated during a fork().
     */
    void detach()
    {
        Error error;

        if (!LSGmainDetach(_handle, error.get()))
            throw error;
        release();
    }

    /**
     * @brief Sets the priority level on the associated GSources for
     *        the service connection.
     *
     *        This should be called after @ref attachToLoop()
     *        See https://developer.gnome.org/glib/2.37/glib-The-Main-Event-Loop.html#g-source-set-priority for details.
     * @param priority priority level
     */
    void setPriority(int priority) const
    {
        Error error;

        if (!LSGmainSetPriority(_handle, priority, error.get()))
            throw error;
    }

    /**
     * Sends a signal specified by URI with given payload to subscribed services.
     * Services register signals with the method registerCategory(). The signal can be fired with sendSignal().
     * Services can subscribe for signals with addmatch.
     *
     * Client subscribe to a signals with method
     * LSCall(sh, "luna://com.webos.service.bus/signal/addmatch", ...)
     *
     * @param uri       fully qualified path to service's method
     * @param payload   some string, usually following json object semantics
     * @param typecheck if true then check if the signal point exists and log a warning if it does not exist
     */
    void sendSignal(const char *uri, const char *payload, bool typecheck = true) const
    {
        Error error;

        if (typecheck)
        {
            if (!LSSignalSend(_handle, uri, payload, error.get()))
                throw error;
        }
        else
        {
            if (!LSSignalSendNoTypecheck(_handle, uri, payload, error.get()))
                throw error;
        }
    }

    /**
     * Make a call
     *
     * @param uri      fully qualified path to service's method
     * @param payload  some string, usually following json object semantics
     * @param appID    application ID
     * @return call control object
     */
    Call callOneReply(const char *uri, const char *payload, const char *appID = NULL)
    {
        Call call;
        call.call(_handle, uri, payload, true, appID);
        return call;
    }

    /**
     * Make a call with result handler callback
     *
     * @param uri      fully qualified path to service's method
     * @param payload  some string, usually following json object semantics
     * @param func     callback function
     * @param context  user data.
     * @param appID    application ID
     * @return call handler object
     */
    Call callOneReply(const char *uri,
                      const char *payload,
                      LSFilterFunc func,
                      void *context,
                      const char *appID = NULL)
    {
        Call call;
        call.continueWith(func, context);
        call.call(_handle, uri, payload, true, appID);
        return call;
    }

    /**
     * @brief Make a multi-call \n
     * Returned object will collect arrived messages in internal queue.
     * Messaged can be obtained with callback or get(...) functions.
     *
     * @param uri      fully qualified path to service's method
     * @param payload  some string, usually following json object semantics
     * @param appID    application id
     * @return call    handler object
     */
    Call callMultiReply(const char *uri, const char *payload, const char *appID = NULL)
    {
        Call call;
        call.call(_handle, uri, payload, false, appID);
        return call;
    }

    /**
     * Make a multi-call with result processing callback
     *
     * @param uri      fully qualified path to service's method
     * @param payload  some string, usually following json object semantics
     * @param func     callback function
     * @param context  context
     * @param appID    application id
     * @return call    handler object
     */
    Call callMultiReply(const char *uri,
                        const char *payload,
                        LSFilterFunc func,
                        void *context,
                        const char *appID = NULL)
    {
        Call call;
        call.continueWith(func, context);
        call.call(_handle, uri, payload, false, appID);
        return call;
    }

    /**
     * Call a signal to a specific category
     *
     * @param category   category name to monitor
     * @param methodName method name to monitor
     * @param func       callback function
     * @param context    user data
     * @return call      handler object
     */
    Call callSignal(const char *category, const char *methodName, LSFilterFunc func, void *context)
    {
        Call call;
        call.continueWith(func, context);
        call.callSignal(_handle, category, methodName);
        return call;
    }

    /**
     * @brief Register a callback to be called when the server goes down or comes up.
     * Callback may be called in this context if
     * the server is already up.
     *
     * @param service_name service name
     * @param callback callback function
     * @return status handler object, control its lifetime to control the subscription
     */
    ServerStatus registerServerStatus(const char *service_name, const ServerStatusCallback &callback)
    { return ServerStatus(_handle, service_name, callback); }

private:
    LSHandle *_handle;

private:
    explicit Handle(LSHandle *handle)
        : _handle(handle)
    { }

    LSHandle *release()
    {
        LSHandle *handle = _handle;
        _handle = nullptr;

        return handle;
    }

    friend std::ostream &operator<<(std::ostream &os, const Handle &service_handle)
    { return os << "LUNA SERVICE '" << service_handle.getName() << "'"; }
};

inline
Handle registerService(const char *name)
{ return { name }; }

inline
Handle registerApplicationService(const char *name, const char *app_id)
{ return { name, app_id }; }

/**
 * @deprecated Avoid specification of unnamed service
 */
Handle registerService(std::nullptr_t = nullptr) LS_DEPRECATED_PUBPRIV;

/**
 * @deprecated Avoid specification of public/service hub
 */
Handle registerService(const char *name, bool public_service) LS_DEPRECATED_PUBPRIV;

} //namespace LS;
