Luna-service2 C++ service example
=============

Summary
-------
This is example usage of LS2 C++ service. This service sends date & time.

How to Build on Linux
=====================

## Dependencies

* cmake (version required by openwebos/cmake-modules-webos)
* gcc 4.8.0
* glib-2.0 2.32.1
* make (any version)
* openwebos/cmake-modules-webos 1.2.0
* openwebos/libpbnjson_cpp 2.11.0
* openwebos/PmLogLib 3.0.2
* pkg-config 0.26
* openwebos/luna-service2++ 1.6

## Edit code
In this template following values means:

    com.webos.webos-native-service-cxx     Service LS2 name
    webos-native-service-cxx               Service binary name

Change value to your own and rename files to your service name.

## Building

Once you have downloaded the source, enter the following to build it (after
changing into the directory under which it was downloaded):

    $ mkdir BUILD
    $ cd BUILD
    $ cmake ..
    $ make
    $ sudo make install

The directory under which the files are installed defaults to `/usr/local/webos`.
You can install them elsewhere by supplying a value for `WEBOS_INSTALL_ROOT`
when invoking `cmake`. For example:

    $ cmake -D WEBOS_INSTALL_ROOT:PATH=$HOME/projects/openwebos ..
    $ make
    $ make install

## Copyright and License Information

Unless otherwise specified, all content, including all source code files and
documentation files in this repository are:

Copyright (c) 2015 LG Electronics

Unless otherwise specified or set forth in the NOTICE file, all content,
including all source code files and documentation files in this repository are:
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this content except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
