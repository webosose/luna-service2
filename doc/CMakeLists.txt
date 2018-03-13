# Copyright (c) 2015-2018 LG Electronics, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0

set(DOC_DIRNAME ls_DOC_-${WEBOS_API_VERSION})
set(LS_DOC_OUTPUT ${WEBOS_BINARY_DOCUMENTATION_DIR}/${CMAKE_PROJECT_NAME}/doc)
set(LS_DOC_C_API_OUT ${LS_DOC_OUTPUT}/c_api)
set(LS_DOC_CXX_API_OUT ${LS_DOC_OUTPUT}/cxx_api)
set(LS_DOC_ALL_API_OUT ${LS_DOC_OUTPUT}/all)

message(STATUS "** documentation output to: ${LS_DOC_OUTPUT}")

foreach(DOC_OUTPUT_DIR ${LS_DOC_C_API_OUT} ${LS_DOC_CXX_API_OUT})
	file(MAKE_DIRECTORY ${DOC_OUTPUT_DIR})
endforeach()

macro(doc_target custom_target lang doxy_filename)
	configure_file(${CMAKE_CURRENT_SOURCE_DIR}/${doxy_filename} ${CMAKE_CURRENT_BINARY_DIR}/${doxy_filename} @ONLY)
	add_custom_target(ls-doc-${custom_target}_${lang}
	                  doxygen ${doxy_filename}
	                  WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
	                  COMMENT "Generating ${custom_target} documentation for ${lang}")
endmacro()

add_custom_target(docs)

doc_target(api c LS2_C.in)
doc_target(api cxx LS2_CXX.in)
doc_target(api all LS2_ALL.in)

add_dependencies(docs ls-doc-api_c ls-doc-api_cxx ls-doc-api_all)
