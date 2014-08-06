/*  vim:expandtab:shiftwidth=2:tabstop=2:smarttab:
 * 
 *  Libmemcached library
 *
 *  Copyright (C) 2011-2012 Data Differential, http://datadifferential.com/
 *  Copyright (C) 2006-2009 Brian Aker All rights reserved.
 *
 *  Redistribution and use in source and binary forms, with or without
 *  modification, are permitted provided that the following conditions are
 *  met:
 *
 *      * Redistributions of source code must retain the above copyright
 *  notice, this list of conditions and the following disclaimer.
 *
 *      * Redistributions in binary form must reproduce the above
 *  copyright notice, this list of conditions and the following disclaimer
 *  in the documentation and/or other materials provided with the
 *  distribution.
 *
 *      * The names of its contributors may not be used to endorse or
 *  promote products derived from this software without specific prior
 *  written permission.
 *
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *  "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *  LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *  A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *  OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *  SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *  LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *  DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *  THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *  OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include "libmemcached/common.h"
#include <cassert>

#define ALIYUN_OCS_SASL_MECH "PLAIN"

memcached_return_t memcached_destroy_sasl_auth_data(memcached_st *shell)
{
  Memcached* ptr = (Memcached *)memcached2Memcached(shell);

  if (ptr->sasl.context != NULL && ptr->sasl.is_allocated)
  {
    libmemcached_free(ptr, ptr->sasl.context->username);
    libmemcached_free(ptr, ptr->sasl.context->password);
    libmemcached_free(ptr, (void*)ptr->sasl.context);
    ptr->sasl.is_allocated = false;
  }
  ptr->sasl.context= NULL;
  return MEMCACHED_SUCCESS;
}

memcached_return_t memcached_set_sasl_auth_data(memcached_st *shell, const char *username, const char *password)
{
  Memcached* ptr= (Memcached *)memcached2Memcached(shell);

  if (ptr == NULL or username == NULL or password == NULL)
  {
    return MEMCACHED_INVALID_ARGUMENTS;
  }

  memcached_return_t ret;
  if (memcached_failed(ret= memcached_behavior_set(ptr, MEMCACHED_BEHAVIOR_BINARY_PROTOCOL, 1)))
  {
    return memcached_set_error(*ptr, ret, MEMCACHED_AT, memcached_literal_param("Unable change to binary protocol which is required for SASL."));
  }

  memcached_destroy_sasl_auth_data(ptr);

  ocs_sasl_context *context= libmemcached_xcalloc(ptr, 4, ocs_sasl_context);
  size_t password_length= strlen(password);
  size_t username_length= strlen(username);
  char *name = (char *)libmemcached_malloc(ptr, username_length +1);
  char *pasw = (char *)libmemcached_malloc(ptr, password_length +1);

  if (context == NULL or name == NULL or pasw == NULL)
  {
    libmemcached_free(ptr, context);
    libmemcached_free(ptr, name);
    libmemcached_free(ptr, pasw);
    return memcached_set_error(*ptr, MEMCACHED_MEMORY_ALLOCATION_FAILURE, MEMCACHED_AT);
  }

  context->username= strncpy(name, username, username_length + 1);
  context->password= strncpy(pasw, password, password_length + 1);

  ptr->sasl.context= context;
  ptr->sasl.is_allocated= true;

  return MEMCACHED_SUCCESS;
}

memcached_return_t memcached_clone_sasl(memcached_st *clone, const  memcached_st *source)
{
  if (clone == NULL or source == NULL)
  {
    return MEMCACHED_INVALID_ARGUMENTS;
  }

  if (source->sasl.context == NULL)
  {
    return MEMCACHED_SUCCESS;
  }

  /* Hopefully we are using our own callback mechanisms.. */
  return memcached_set_sasl_auth_data(clone,
                                      source->sasl.context->username,
                                      source->sasl.context->password);
}

memcached_return_t memcached_sasl_authenticate_connection(memcached_instance_st* server)
{
  if (server == NULL)
  {
    return MEMCACHED_INVALID_ARGUMENTS;
  }

  /* SANITY CHECK: SASL can only be used with the binary protocol */
  if (memcached_is_binary(server->root) == false)
  {
    return  memcached_set_error(*server, MEMCACHED_INVALID_ARGUMENTS, MEMCACHED_AT,
                                memcached_literal_param("memcached_sasl_authenticate_connection() is not supported via the ASCII protocol"));
  }

  /**
   * OCS just supoort PLAIN-MECH
 */
  unsigned int userlen= strlen(server->root->sasl.context->username) + 1;
  unsigned int paswlen= strlen(server->root->sasl.context->password);
  unsigned int vallen = userlen + paswlen + 1;
  char *data= (char *)malloc(vallen);
  data[0] = '\0';
  strncpy(data + 1, server->root->sasl.context->username, userlen);
  strncpy(data + 1 + userlen, server->root->sasl.context->password, paswlen);
  uint16_t keylen= (uint16_t)strlen(ALIYUN_OCS_SASL_MECH);

  protocol_binary_request_no_extras request= { };
  initialize_binary_request(server, request.message.header);
  request.message.header.request.opcode= PROTOCOL_BINARY_CMD_SASL_AUTH;
  request.message.header.request.keylen= htons(keylen);
  request.message.header.request.bodylen= htonl(vallen + keylen);

    /* send the packet */
    libmemcached_io_vector_st vector[]=
    {
      { request.bytes, sizeof(request.bytes) },
    { ALIYUN_OCS_SASL_MECH, keylen },
    { data, vallen }
    };

  memcached_return_t rc= MEMCACHED_SUCCESS;
    assert_msg(server->fd != INVALID_SOCKET, "Programmer error, invalid socket");
    if (memcached_io_writev(server, vector, 3, true) == false)
    {
      rc= MEMCACHED_WRITE_FAILURE;
    }
  else
  {
    assert_msg(server->fd != INVALID_SOCKET, "Programmer error, invalid socket");
    memcached_server_response_increment(server);
    /* read the response */
    assert_msg(server->fd != INVALID_SOCKET, "Programmer error, invalid socket");
    rc= memcached_response(server, NULL, 0, NULL);
    }
  free(data);
  return memcached_set_error(*server, rc, MEMCACHED_AT);
}

