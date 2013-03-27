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

import org.elasticsearch.client.Client;
import org.elasticsearch.common.settings.ImmutableSettings;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.network.NetworkUtils;
import org.elasticsearch.common.unit.TimeValue;
import org.elasticsearch.common.xcontent.XContentBuilder;
import org.elasticsearch.common.xcontent.XContentFactory;
import org.elasticsearch.node.Node;

import org.elasticsearch.index.query.FilterBuilder;
import org.elasticsearch.action.search.SearchResponse;
import org.elasticsearch.index.query.QueryBuilders;

import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import org.eclipse.jetty.servlet.ServletHolder;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.servlet.ServletContextHandler;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import java.io.IOException;
import java.util.Map;
import java.util.HashMap;
import java.util.List;
import java.util.ArrayList;

import static org.elasticsearch.client.Requests.*;
import static org.elasticsearch.index.query.QueryBuilders.*;
import static org.elasticsearch.common.settings.ImmutableSettings.Builder.EMPTY_SETTINGS;
import static org.elasticsearch.common.settings.ImmutableSettings.settingsBuilder;
import static org.elasticsearch.node.NodeBuilder.nodeBuilder;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.nullValue;


/** This class tests the MCFAuthorizer class in an integration-test fashion.
*/
public class MCFAuthorizerTest
{
  // Set this to true if null_value is ever fixed in ES
  protected final static boolean useNullValue = false;
  
  protected Client client;
  protected MockMCFAuthorityService service;

  @BeforeClass
  public void startMCFAuthorityService() throws Exception {
    service = new MockMCFAuthorityService();
    service.start();
  }

  @AfterClass
  public void afterClass() throws Exception {
    service.stop();
  }

  @BeforeClass
  public void startNodes() throws IOException {
    startNode("server", nodeSettings());
    client = getClient();
    createIndex();
  }

  @Test
  public void simpleTest() throws Exception
  {
    // Sanity check to be sure I indexed everything right...
    SearchResponse allResponse = client.prepareSearch("test").setQuery(QueryBuilders.matchAllQuery()).execute().actionGet();
    verifyResponse(allResponse, "da12", "da13-dd3", "sa123-sd13", "sa3-sd1-da23", "notoken");
    SearchResponse partialResponse = client.prepareSearch("test").setQuery(QueryBuilders.termQuery("allow_token_share","token1")).execute().actionGet();
    verifyResponse(partialResponse, "sa123-sd13");
    SearchResponse nullResponse = client.prepareSearch("test").setQuery(QueryBuilders.termQuery("allow_token_share","__nosecurity__")).execute().actionGet();
    verifyResponse(nullResponse, "da12", "da13-dd3", "notoken");

    ConfigurationParameters cp = new ConfigurationParameters();
    MCFAuthorizer mcfa = new MCFAuthorizer(cp);
    FilterBuilder user1Filter = mcfa.buildAuthorizationFilter("user1");
    FilterBuilder user2Filter = mcfa.buildAuthorizationFilter("user2");
    FilterBuilder user3Filter = mcfa.buildAuthorizationFilter("user3");
    FilterBuilder user4Filter = mcfa.buildAuthorizationFilter("user4");
    
    // Ok, check the filters I built.
    SearchResponse user1Response = client.prepareSearch("test").setQuery(QueryBuilders.matchAllQuery()).setFilter(user1Filter).execute().actionGet();
    verifyResponse(user1Response, "da12", "da13-dd3", "notoken");
    SearchResponse user2Response = client.prepareSearch("test").setQuery(QueryBuilders.matchAllQuery()).setFilter(user2Filter).execute().actionGet();
    verifyResponse(user2Response, "da12", "da13-dd3", "notoken");
    SearchResponse user3Response = client.prepareSearch("test").setQuery(QueryBuilders.matchAllQuery()).setFilter(user3Filter).execute().actionGet();
    verifyResponse(user3Response, "da12", "notoken");
    SearchResponse user4Response = client.prepareSearch("test").setQuery(QueryBuilders.matchAllQuery()).setFilter(user4Filter).execute().actionGet();
    verifyResponse(user4Response, "notoken");
  }
  
  protected static void verifyResponse(SearchResponse userResponse, String... docIDs)
    throws Exception
  {
    System.out.println("Total filtered hits: "+userResponse.getHits().totalHits());
    assertThat(userResponse.getHits().totalHits(), equalTo((long)docIDs.length));
    // MHL for full check
  }
  
  protected void createIndex()
    throws IOException {
    try {
      client.admin().indices().prepareDelete("test").execute().actionGet();
    } catch (Exception e) {
      // ignore
    }
    
    // Question: We need the equivalent of default field values.  How do we set that in ElasticSearch?
    // Mappings with null_value are supposed to do that, but I can't get them to work.
    if (useNullValue)
    {
      client.admin().indices().create(
        createIndexRequest("test")
          .mapping("type1",aclsource())
        ).actionGet();
    }
    else
    {
      client.admin().indices().create(
        createIndexRequest("test")
        ).actionGet();
    }
    
    //             |     share    |   document
    //             |--------------|--------------
    //             | allow | deny | allow | deny
    // ------------+-------+------+-------+------
    // da12        |       |      | 1, 2  |
    // ------------+-------+------+-------+------
    // da13-dd3    |       |      | 1,3   | 3
    // ------------+-------+------+-------+------
    // sa123-sd13  | 1,2,3 | 1, 3 |       |
    // ------------+-------+------+-------+------
    // sa3-sd1-da23| 3     | 1    | 2,3   |
    // ------------+-------+------+-------+------
    // notoken     |       |      |       |
    // ------------+-------+------+-------+------
    //
    if (useNullValue)
    {
      addDoc("da12",
        "allow_token_document", "token1",
        "allow_token_document", "token2");
      addDoc("da13-dd3",
        "allow_token_document", "token1",
        "allow_token_document", "token3",
        "deny_token_document", "token3");
      addDoc("sa123-sd13",
        "allow_token_share", "token1",
        "allow_token_share", "token2",
        "allow_token_share", "token3",
        "deny_token_share", "token1",
        "deny_token_share", "token3");
      addDoc("sa3-sd1-da23",
        "allow_token_document", "token2",
        "allow_token_document", "token3",
        "allow_token_share", "token3",
        "deny_token_share", "token1");
      addDoc("notoken");
    }
    else
    {
      addDoc("da12",
        "allow_token_document", "token1",
        "allow_token_document", "token2",
        "deny_token_document", "__nosecurity__",
        "allow_token_share", "__nosecurity__",
        "deny_token_share", "__nosecurity__"
      );
      addDoc("da13-dd3",
        "allow_token_document", "token1",
        "allow_token_document", "token3",
        "deny_token_document", "token3",
        "allow_token_share", "__nosecurity__",
        "deny_token_share", "__nosecurity__"
      );
      addDoc("sa123-sd13",
        "allow_token_share", "token1",
        "allow_token_share", "token2",
        "allow_token_share", "token3",
        "deny_token_share", "token1",
        "deny_token_share", "token3",
        "allow_token_document", "__nosecurity__",
        "deny_token_document", "__nosecurity__"
      );
      addDoc("sa3-sd1-da23",
        "allow_token_document", "token2",
        "allow_token_document", "token3",
        "allow_token_share", "token3",
        "deny_token_share", "token1",
        "deny_token_document", "__nosecurity__"
      );
      addDoc("notoken",
        "allow_token_document", "__nosecurity__",
        "deny_token_document", "__nosecurity__",
        "allow_token_share", "__nosecurity__",
        "deny_token_share", "__nosecurity__"
      );
    }
    commit();
  }

  protected Settings nodeSettings() {
    return ImmutableSettings.Builder.EMPTY_SETTINGS;
  }

  protected String getConcreteIndexName() {
    return "test";
  }

  protected void addDoc(String docID,
    String... argPairs)
    throws IOException
  {
    client.prepareIndex().setIndex("test")
      .setType("type1").setId(docID)
      .setSource(source(docID,argPairs))
      .setRefresh(true).execute().actionGet();
  }
  
  protected void commit()
  {
    client.admin().indices().prepareRefresh("test").execute().actionGet();
  }
  
  @AfterClass
  public void closeNodes() {
    client.close();
    closeAllNodes();
  }

  protected Client getClient() {
    return client("server");
  }
  
  private static XContentBuilder aclsource() throws IOException
  {
    XContentBuilder builder = XContentFactory.jsonBuilder()
      .startObject()
      .startObject("type1")
      .startObject("properties");
    addField(builder,"allow_token_document");
    addField(builder,"allow_token_share");
    addField(builder,"deny_token_document");
    addField(builder,"deny_token_share");
    builder.endObject()
      .endObject()
      .endObject();
    return builder;
  }
  
  private static void addField(XContentBuilder builder, String fieldName)
    throws IOException
  {
    builder.startObject(fieldName)
      .field("type","string")
      .field("null_value","__nosecurity__")
      .endObject();
  }
  
  private static XContentBuilder source(String id, String... argPairs) throws IOException {
    XContentBuilder builder = XContentFactory.jsonBuilder()
      .startObject()
      .startObject("type1").field("id", id);
    
    Map<String,List<String>> allValues = new HashMap<String,List<String>>();
    
    int pairCount = argPairs.length >> 1;
    for (int i = 0; i < pairCount; i++)
    {
      String fieldName = argPairs[i*2];
      String fieldValue = argPairs[i*2+1];
      List<String> values = allValues.get(fieldName);
      if (values == null)
      {
        values = new ArrayList<String>();
        allValues.put(fieldName,values);
      }
      values.add(fieldValue);
    }

    for (String fieldName : allValues.keySet())
    {
      builder.field(fieldName, allValues.get(fieldName).toArray(new String[0]));
    }
    
    builder.endObject()
      .endObject();
    return builder;
  }
    
  static class MockMCFAuthorityService {
    
    Server server;
    
    public MockMCFAuthorityService() {
      // Start jetty
      server = new Server( 8345 );    
      server.setStopAtShutdown( true );
      // Initialize the servlet
      ServletContextHandler context = new ServletContextHandler(ServletContextHandler.SESSIONS);
      context.setInitParameter("org.eclipse.jetty.servlet.SessionIdPathParameterName","none");
      context.setContextPath("/mcf-authority-service");
      server.setHandler(context);
      context.addServlet(new ServletHolder(new UserACLServlet()), "/UserACLs");
    }
    
    public void start() throws Exception {
      server.start();
    }
    
    public void stop() throws Exception {
      server.stop();
    }

    // username | tokens rewarded
    // ---------+-------------------------------
    // null     | (no tokens)
    // user1    | token1
    // user2    | token1, token2
    // user3    | token1, token2, token3
    public static class UserACLServlet extends HttpServlet {
      @Override
      public void service(HttpServletRequest req, HttpServletResponse res)
          throws IOException {
        String user = req.getParameter("username");
        res.setStatus(HttpServletResponse.SC_OK);
        if(user.equals("user1") || user.equals("user2") || user.equals("user3"))
          res.getWriter().printf("TOKEN:token1\n");
        if(user.equals("user2") || user.equals("user3"))
          res.getWriter().printf("TOKEN:token2\n");
        if(user.equals("user3"))
          res.getWriter().printf("TOKEN:token3\n");
      }
    }
  }

  // Test helper methods
  
  private Map<String, Node> nodes = new HashMap<String,Node>();

  private Map<String, Client> clients = new HashMap<String,Client>();

  private Settings defaultSettings = ImmutableSettings
          .settingsBuilder()
          .put("cluster.name", "test-cluster-" + NetworkUtils.getLocalAddress().getHostName())
          .build();

  public void putDefaultSettings(Settings.Builder settings) {
    putDefaultSettings(settings.build());
  }

  public void putDefaultSettings(Settings settings) {
    defaultSettings = ImmutableSettings.settingsBuilder().put(defaultSettings).put(settings).build();
  }

  public Node startNode(String id) {
    return buildNode(id).start();
  }

  public Node startNode(String id, Settings.Builder settings) {
    return startNode(id, settings.build());
  }

  public Node startNode(String id, Settings settings) {
    return buildNode(id, settings).start();
  }

  public Node buildNode(String id) {
    return buildNode(id, EMPTY_SETTINGS);
  }

  public Node buildNode(String id, Settings.Builder settings) {
    return buildNode(id, settings.build());
  }

  public Node buildNode(String id, Settings settings) {
    String settingsSource = getClass().getName().replace('.', '/') + ".yml";
    Settings finalSettings = settingsBuilder()
            .loadFromClasspath(settingsSource)
            .put(defaultSettings)
            .put(settings)
            .put("name", id)
            .build();

    if (finalSettings.get("gateway.type") == null) {
      // default to non gateway
      finalSettings = settingsBuilder().put(finalSettings).put("gateway.type", "none").build();
    }
    if (finalSettings.get("cluster.routing.schedule") != null) {
      // decrease the routing schedule so new nodes will be added quickly
      finalSettings = settingsBuilder().put(finalSettings).put("cluster.routing.schedule", "50ms").build();
    }

    Node node = nodeBuilder()
          .settings(finalSettings)
          .build();
    nodes.put(id, node);
    clients.put(id, node.client());
    return node;
  }

  public void closeNode(String id) {
    Client client = clients.remove(id);
    if (client != null) {
      client.close();
    }
    Node node = nodes.remove(id);
    if (node != null) {
      node.close();
    }
  }

  public Node node(String id) {
    return nodes.get(id);
  }

  public Client client(String id) {
    return clients.get(id);
  }

  public void closeAllNodes() {
    for (Client client : clients.values()) {
      client.close();
    }
    clients.clear();
    for (Node node : nodes.values()) {
      node.close();
    }
    nodes.clear();
  }

}
