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

import org.apache.lucene.search.*;

/** This class represents the main Java API for modifying Lucene queries
* within ElasticSearch.  It is a singleton class whose main public method
* is thread-safe.
*/
public class QueryModifier
{
  protected final ConfigurationParameters configurationParameters;

  /** Constructor, which includes configuration information */
  public QueryModifier(ConfigurationParameters cp)
  {
    this.configurationParameters = cp;
  }
  
  /** Main method for wrapping a query with appropriate security.
  */
  public Query wrapQuery(Query userQuery, String authenticatedUserName)
    throws QueryModifierException
  {
    // MHL
    return null;
  }
  
}
