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

import java.io.*;
import java.util.*;
import java.net.*;

import org.elasticsearch.index.query.FilterBuilder;
import org.elasticsearch.index.query.BoolFilterBuilder;
import org.elasticsearch.index.query.TermFilterBuilder;

import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.HttpResponse;
import org.apache.http.params.BasicHttpParams;
import org.apache.http.params.CoreConnectionPNames;
import org.apache.http.util.EntityUtils;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.impl.client.DefaultRedirectStrategy;
import org.apache.http.conn.ClientConnectionManager;
import org.apache.http.impl.conn.PoolingClientConnectionManager;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/** This class represents the main Java API for modifying SearchRequestBuilder 
* objects within ElasticSearch.  It is a singleton class whose main public method
* is thread-safe.
*/
public class MCFAuthorizer
{
  
  /** Special token for null security fields */
  static final public String NOSECURITY_TOKEN = "__nosecurity__";

  /** A logger we can use */
  private static final Logger LOG = LoggerFactory.getLogger(MCFAuthorizer.class);

  // Member variables

  protected final String authorityBaseURL;
  protected final String fieldAllowDocument;
  protected final String fieldDenyDocument;
  protected final String fieldAllowParent;
  protected final String fieldDenyParent;
  protected final String fieldAllowShare;
  protected final String fieldDenyShare;
  protected final int connectionTimeout;
  protected final int socketTimeout;
  protected final int poolSize;
  
  protected final ClientConnectionManager connectionManager;
  protected final HttpClient httpClient;

  /** Constructor, which includes configuration information */
  public MCFAuthorizer(ConfigurationParameters cp)
  {
    authorityBaseURL = cp.authorityServiceBaseURL;
    fieldAllowDocument = cp.allowFieldPrefix+"document";
    fieldDenyDocument = cp.denyFieldPrefix+"document";
    fieldAllowShare = cp.allowFieldPrefix+"share";
    fieldDenyShare = cp.denyFieldPrefix+"share";
    fieldAllowParent = cp.allowFieldPrefix+"parent";
    fieldDenyParent = cp.denyFieldPrefix+"parent";
    connectionTimeout = cp.connectionTimeout;
    socketTimeout = cp.socketTimeout;
    poolSize = cp.connectionPoolSize;
    
    // Set up client pool etc, if there's indication that we should do that
    if (authorityBaseURL != null)
    {
      PoolingClientConnectionManager localConnectionManager = new PoolingClientConnectionManager();
      localConnectionManager.setMaxTotal(poolSize);
      localConnectionManager.setDefaultMaxPerRoute(poolSize);
      connectionManager = localConnectionManager;
      
      BasicHttpParams params = new BasicHttpParams();
      params.setBooleanParameter(CoreConnectionPNames.TCP_NODELAY,true);
      params.setBooleanParameter(CoreConnectionPNames.STALE_CONNECTION_CHECK,true);
      params.setIntParameter(CoreConnectionPNames.SO_TIMEOUT,socketTimeout);
      params.setIntParameter(CoreConnectionPNames.CONNECTION_TIMEOUT,connectionTimeout);
      DefaultHttpClient localClient = new DefaultHttpClient(connectionManager,params);
      localClient.setRedirectStrategy(new DefaultRedirectStrategy());
      httpClient = localClient;
    }
    else
    {
      connectionManager = null;
      httpClient = null;
    }
  }

  /** Shut down the pool etc.
  */
  public void shutdown()
  {
    if (connectionManager != null)
      connectionManager.shutdown();
  }

  /** Main method for building a filter representing appropriate security.
  *@param domainMap is a map from MCF authorization domain name to user name,
  * and describes a complete user identity.
  *@return the filter builder.
  */
  public FilterBuilder buildAuthorizationFilter(Map<String,String> domainMap)
    throws AuthorizerException
  {
    if (authorityBaseURL == null)
      throw new IllegalStateException("Authority base URL required for finding access tokens for a user");
    
    if (domainMap == null || domainMap.size() == 0)
      throw new IllegalArgumentException("Cannot find user tokens for null user");

    if(LOG.isInfoEnabled()){
      StringBuilder sb = new StringBuilder("[");
      boolean first = true;
      for (String domain : domainMap.keySet())
      {
        if (!first)
          sb.append(",");
        else
          first = false;
        sb.append(domain).append(":").append(domainMap.get(domain));
      }
      sb.append("]");
      LOG.info("Trying to match docs for user '"+sb.toString()+"'");
    }

    return buildAuthorizationFilter(getAccessTokens(domainMap));
  }
  
  /** Main method for building a filter representing appropriate security.
  *@param authenticatedUserName is a user name in the form "user@domain".
  *@return the filter builder.
  */
  public FilterBuilder buildAuthorizationFilter(String authenticatedUserName)
    throws AuthorizerException
  {
    return buildAuthorizationFilter(authenticatedUserName, "");
  }
  
  /** Main method for building a filter representing appropriate security.
  *@param authenticatedUserName is a user name in the form "user@domain".
  *@param authenticatedUserDomain is the corresponding MCF authorization domain.
  *@return the filter builder.
  */
  public FilterBuilder buildAuthorizationFilter(String authenticatedUserName, String authenticatedUserDomain)
    throws AuthorizerException
  {
    Map<String,String> domainMap = new HashMap<String,String>();
    domainMap.put(authenticatedUserDomain, authenticatedUserName);
    return buildAuthorizationFilter(domainMap);
  }

  /** Main method for building a filter representing appropriate security.
  *@param userAccessTokens are a set of tokens to use to construct the filter (presumably from mod_authz_annotate, upstream)
  *@return the wrapped query enforcing ManifoldCF security.
  */
  public FilterBuilder buildAuthorizationFilter(List<String> userAccessTokens)
    throws AuthorizerException
  {
    BoolFilterBuilder bq = new BoolFilterBuilder();
    
    FilterBuilder allowShareOpen = new TermFilterBuilder(fieldAllowShare,NOSECURITY_TOKEN);
    FilterBuilder denyShareOpen = new TermFilterBuilder(fieldDenyShare,NOSECURITY_TOKEN);
    FilterBuilder allowParentOpen = new TermFilterBuilder(fieldAllowParent,NOSECURITY_TOKEN);
    FilterBuilder denyParentOpen = new TermFilterBuilder(fieldDenyParent,NOSECURITY_TOKEN);
    FilterBuilder allowDocumentOpen = new TermFilterBuilder(fieldAllowDocument,NOSECURITY_TOKEN);
    FilterBuilder denyDocumentOpen = new TermFilterBuilder(fieldDenyDocument,NOSECURITY_TOKEN);
    
    if (userAccessTokens == null || userAccessTokens.size() == 0)
    {
      // Only open documents can be included.
      // That query is:
      // (fieldAllowShare is empty AND fieldDenyShare is empty AND fieldAllowDocument is empty AND fieldDenyDocument is empty)
      // We're trying to map to:  -(fieldAllowShare:*) , which should be pretty efficient in Solr because it is negated.  If this turns out not to be so, then we should
      // have the SolrConnector inject a special token into these fields when they otherwise would be empty, and we can trivially match on that token.
      bq.must(allowShareOpen);
      bq.must(denyShareOpen);
      bq.must(allowParentOpen);
      bq.must(denyParentOpen);
      bq.must(allowDocumentOpen);
      bq.must(denyDocumentOpen);
    }
    else
    {
      // Extend the query appropriately for each user access token.
      bq.must(calculateCompleteSubquery(fieldAllowShare,fieldDenyShare,allowShareOpen,denyShareOpen,userAccessTokens));
      bq.must(calculateCompleteSubquery(fieldAllowDocument,fieldDenyDocument,allowDocumentOpen,denyDocumentOpen,userAccessTokens));
      bq.must(calculateCompleteSubquery(fieldAllowParent,fieldDenyParent,allowParentOpen,denyParentOpen,userAccessTokens));
    }

    return bq;
  }

  /** Calculate a complete subclause, representing something like:
  * ((fieldAllowShare is empty AND fieldDenyShare is empty) OR fieldAllowShare HAS token1 OR fieldAllowShare HAS token2 ...)
  *     AND fieldDenyShare DOESN'T_HAVE token1 AND fieldDenyShare DOESN'T_HAVE token2 ...
  */
  protected static FilterBuilder calculateCompleteSubquery(String allowField, String denyField, FilterBuilder allowOpen, FilterBuilder denyOpen, List<String> userAccessTokens)
  {
    BoolFilterBuilder bq = new BoolFilterBuilder();
    // No ES equivalent - hope this is done right inside
    //bq.setMaxClauseCount(1000000);
    
    // Add the empty-acl case
    BoolFilterBuilder subUnprotectedClause = new BoolFilterBuilder();
    subUnprotectedClause.must(allowOpen);
    subUnprotectedClause.must(denyOpen);
    bq.should(subUnprotectedClause);
    for (String accessToken : userAccessTokens)
    {
      bq.should(new TermFilterBuilder(allowField,accessToken));
      bq.mustNot(new TermFilterBuilder(denyField,accessToken));
    }
    return bq;
  }

  /** Get access tokens given a username */
  protected List<String> getAccessTokens(Map<String,String> domainMap)
    throws AuthorizerException
  {
    try
    {
      StringBuilder urlBuffer = new StringBuilder(authorityBaseURL);
      urlBuffer.append("/UserACLs");
      int i = 0;
      for (String domain : domainMap.keySet())
      {
        if (i == 0)
          urlBuffer.append("?");
        else
          urlBuffer.append("&");
        // For backwards compatibility, handle the singleton case specially
        if (domainMap.size() == 1 && domain.length() == 0)
        {
          urlBuffer.append("username=").append(URLEncoder.encode(domainMap.get(domain),"utf-8"));
        }
        else
        {
          urlBuffer.append("username_").append(Integer.toString(i)).append("=").append(URLEncoder.encode(domainMap.get(domain),"utf-8")).append("&")
            .append("domain_").append(Integer.toString(i)).append("=").append(URLEncoder.encode(domain,"utf-8"));
        }
        i++;
      }
      String theURL = urlBuffer.toString();

      HttpGet method = new HttpGet(theURL);
      try
      {
        HttpResponse httpResponse = httpClient.execute(method);
        int rval = httpResponse.getStatusLine().getStatusCode();
        if (rval != 200)
        {
          String response = EntityUtils.toString(httpResponse.getEntity(),"utf-8");
          throw new AuthorizerException("Couldn't fetch user's access tokens from ManifoldCF authority service: "+Integer.toString(rval)+"; "+response);
        }
        InputStream is = httpResponse.getEntity().getContent();
        try
        {
          String charSet = EntityUtils.getContentCharSet(httpResponse.getEntity());
          if (charSet == null)
            charSet = "utf-8";
          Reader r = new InputStreamReader(is,charSet);
          try
          {
            BufferedReader br = new BufferedReader(r);
            try
            {
              // Read the tokens, one line at a time.  If any authorities are down, we have no current way to note that, but someday we will.
              List<String> tokenList = new ArrayList<String>();
              while (true)
              {
                String line = br.readLine();
                if (line == null)
                  break;
                if (line.startsWith("TOKEN:"))
                {
                  tokenList.add(line.substring("TOKEN:".length()));
                }
                else
                {
                  // It probably says something about the state of the authority(s) involved, so log it
                  LOG.info("Saw authority response "+line);
                }
              }
              return tokenList;
            }
            finally
            {
              br.close();
            }
          }
          finally
          {
            r.close();
          }
        }
        finally
        {
          is.close();
        }
      }
      finally
      {
        method.abort();
      }
    }
    catch (IOException e)
    {
      throw new AuthorizerException("IO exception: "+e.getMessage(),e);
    }
  }

}
