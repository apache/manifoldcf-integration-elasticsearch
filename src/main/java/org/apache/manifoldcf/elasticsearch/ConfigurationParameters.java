/* $Id$ */

/**
* Licensed to the Apache Software Foundation (ASF) under one or more
* contributor license agreements. See the NOTICE file distributed with
* this work for additional information regarding copyright ownership.
* The ASF licenses this file to You under the Apache License, Version 2.0
* (the "License"); you may not use this file except in compliance with
* the License. You may obtain a copy of the License at
*
* http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*/
package org.apache.manifoldcf.elasticsearch;

/** This class represents the configuration information that the QueryModifier
* needs to perform its job.
*/
public class ConfigurationParameters
{
  /** Base URL, e.g. "http://localhost:8345/mcf-authority-service" */
  public String authorityServiceBaseURL = "http://localhost:8345/mcf-authority-service";
  /** Connection timeout, e.g. 60000 */
  public int connectionTimeout = 60000;
  /** Socket timeout, e.g. 300000 */
  public int socketTimeout = 300000;
  /** Allow field prefix, e.g. "allow_token_" */
  public String allowFieldPrefix = "allow_token_";
  /** Deny field prefix, e.g. "deny_token_" */
  public String denyFieldPrefix = "deny_token_";
  /** Connection pool size, e.g. 50 */
  public int connectionPoolSize = 50;
  
  public ConfigurationParameters setBaseURL(String baseURL)
  {
    this.authorityServiceBaseURL = baseURL;
    return this;
  }
  
  public ConfigurationParameters setConnectionTimeout(int timeout)
  {
    this.connectionTimeout = timeout;
    return this;
  }
  
  public ConfigurationParameters setSocketTimeout(int timeout)
  {
    this.socketTimeout = timeout;
    return this;
  }
  
  public ConfigurationParameters setAllowFieldPrefix(String prefix)
  {
    this.allowFieldPrefix = prefix;
    return this;
  }
  
  public ConfigurationParameters setDenyFieldPrefix(String prefix)
  {
    this.denyFieldPrefix = prefix;
    return this;
  }
  
  public ConfigurationParameters setConnectionPoolSize(int size)
  {
    this.connectionPoolSize = size;
    return this;
  }
  
}