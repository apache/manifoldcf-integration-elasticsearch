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

import org.apache.lucene.search.*;
import org.apache.lucene.index.*;

import org.apache.http.client.HttpClient;
import org.apache.http.HttpStatus;
import org.apache.http.HttpException;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.conn.ConnectTimeoutException;
import org.apache.http.HttpResponse;
import org.apache.http.params.BasicHttpParams;
import org.apache.http.params.HttpParams;
import org.apache.http.params.CoreConnectionPNames;
import org.apache.http.util.EntityUtils;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.impl.client.DefaultRedirectStrategy;
import org.apache.http.conn.ClientConnectionManager;
import org.apache.http.impl.conn.PoolingClientConnectionManager;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/** This class represents the main Java API for modifying Lucene queries
* within ElasticSearch.  It is a singleton class whose main public method
* is thread-safe.
*/
public class QueryModifier
{
  
  /** Special token for null security fields */
  static final public String NOSECURITY_TOKEN = "__nosecurity__";

  /** A logger we can use */
  private static final Logger LOG = LoggerFactory.getLogger(QueryModifier.class);

  // Member variables

  protected final String authorityBaseURL;
  protected final String fieldAllowDocument;
  protected final String fieldDenyDocument;
  protected final String fieldAllowShare;
  protected final String fieldDenyShare;
  protected final int connectionTimeout;
  protected final int socketTimeout;
  protected final int poolSize;
  
  protected final ClientConnectionManager connectionManager;
  protected final HttpClient httpClient;

  /** Constructor, which includes configuration information */
  public QueryModifier(ConfigurationParameters cp)
  {
    authorityBaseURL = cp.authorityServiceBaseURL;
    fieldAllowDocument = cp.allowFieldPrefix+"document";
    fieldDenyDocument = cp.denyFieldPrefix+"document";
    fieldAllowShare = cp.allowFieldPrefix+"share";
    fieldDenyShare = cp.denyFieldPrefix+"share";
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
      params.setBooleanParameter(CoreConnectionPNames.STALE_CONNECTION_CHECK,false);
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
    if (authorityBaseURL != null)
      connectionManager.shutdown();
  }
  
  /** Main method for wrapping a query with appropriate security.
  *@param userQuery is the user query to wrap.
  *@param authenticatedUserName is a user name in the form "user@domain".
  *@return the wrapped query enforcing ManifoldCF security.
  */
  public Query wrapQuery(Query userQuery, String authenticatedUserName)
    throws QueryModifierException
  {
    if (authorityBaseURL == null)
      throw new IllegalStateException("Authority base URL required for finding access tokens for a user");
    
    if (authenticatedUserName == null)
      throw new IllegalArgumentException("Cannot find user tokens for null user");

    LOG.info("Trying to match docs for user '"+authenticatedUserName+"'");

    return wrapQuery(userQuery,getAccessTokens(authenticatedUserName));
  }

  /** Main method for wrapping a query with appropriate security.
  *@param userQuery is the user query to wrap.
  *@param userAccessTokens are a set of tokens to use to wrap the query (presumably from mod_authz_annotate, upstream)
  *@return the wrapped query enforcing ManifoldCF security.
  */
  public Query wrapQuery(Query userQuery, List<String> userAccessTokens)
    throws QueryModifierException
  {
    BooleanQuery bq = new BooleanQuery();
    
    Query allowShareOpen = new TermQuery(new Term(fieldAllowShare,NOSECURITY_TOKEN));
    Query denyShareOpen = new TermQuery(new Term(fieldDenyShare,NOSECURITY_TOKEN));
    Query allowDocumentOpen = new TermQuery(new Term(fieldAllowDocument,NOSECURITY_TOKEN));
    Query denyDocumentOpen = new TermQuery(new Term(fieldDenyDocument,NOSECURITY_TOKEN));
    
    if (userAccessTokens == null || userAccessTokens.size() == 0)
    {
      // Only open documents can be included.
      // That query is:
      // (fieldAllowShare is empty AND fieldDenyShare is empty AND fieldAllowDocument is empty AND fieldDenyDocument is empty)
      // We're trying to map to:  -(fieldAllowShare:*) , which should be pretty efficient in Solr because it is negated.  If this turns out not to be so, then we should
      // have the SolrConnector inject a special token into these fields when they otherwise would be empty, and we can trivially match on that token.
      bq.add(allowShareOpen,BooleanClause.Occur.MUST);
      bq.add(denyShareOpen,BooleanClause.Occur.MUST);
      bq.add(allowDocumentOpen,BooleanClause.Occur.MUST);
      bq.add(denyDocumentOpen,BooleanClause.Occur.MUST);
    }
    else
    {
      // Extend the query appropriately for each user access token.
      bq.add(calculateCompleteSubquery(fieldAllowShare,fieldDenyShare,allowShareOpen,denyShareOpen,userAccessTokens),
        BooleanClause.Occur.MUST);
      bq.add(calculateCompleteSubquery(fieldAllowDocument,fieldDenyDocument,allowDocumentOpen,denyDocumentOpen,userAccessTokens),
        BooleanClause.Occur.MUST);
    }

    // Concatenate with the user's original query.
    BooleanQuery rval = new BooleanQuery();
    rval.add(new ConstantScoreQuery(bq),BooleanClause.Occur.MUST);
    rval.add(userQuery,BooleanClause.Occur.MUST);
    return rval;
  }

  /** Calculate a complete subclause, representing something like:
  * ((fieldAllowShare is empty AND fieldDenyShare is empty) OR fieldAllowShare HAS token1 OR fieldAllowShare HAS token2 ...)
  *     AND fieldDenyShare DOESN'T_HAVE token1 AND fieldDenyShare DOESN'T_HAVE token2 ...
  */
  protected static Query calculateCompleteSubquery(String allowField, String denyField, Query allowOpen, Query denyOpen, List<String> userAccessTokens)
  {
    BooleanQuery bq = new BooleanQuery();
    bq.setMaxClauseCount(1000000);
    
    // Add the empty-acl case
    BooleanQuery subUnprotectedClause = new BooleanQuery();
    subUnprotectedClause.add(allowOpen,BooleanClause.Occur.MUST);
    subUnprotectedClause.add(denyOpen,BooleanClause.Occur.MUST);
    bq.add(subUnprotectedClause,BooleanClause.Occur.SHOULD);
    for (String accessToken : userAccessTokens)
    {
      bq.add(new TermQuery(new Term(allowField,accessToken)),BooleanClause.Occur.SHOULD);
      bq.add(new TermQuery(new Term(denyField,accessToken)),BooleanClause.Occur.MUST_NOT);
    }
    return bq;
  }

  /** Get access tokens given a username */
  protected List<String> getAccessTokens(String authenticatedUserName)
    throws QueryModifierException
  {
    try
    {
      String theURL = authorityBaseURL + "/UserACLs?username="+URLEncoder.encode(authenticatedUserName,"utf-8");
      HttpGet method = new HttpGet(theURL);
      try
      {
        HttpResponse httpResponse = httpClient.execute(method);
        int rval = httpResponse.getStatusLine().getStatusCode();
        if (rval != 200)
        {
          String response = EntityUtils.toString(httpResponse.getEntity(),"utf-8");
          throw new QueryModifierException("Couldn't fetch user's access tokens from ManifoldCF authority service: "+Integer.toString(rval)+"; "+response);
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
                  LOG.info("For user '"+authenticatedUserName+"', saw authority response "+line);
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
      throw new QueryModifierException("IO exception: "+e.getMessage(),e);
    }
  }

}
