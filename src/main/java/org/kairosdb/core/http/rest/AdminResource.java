package org.kairosdb.core.http.rest;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import org.kairosdb.core.datastore.QueryMetric;
import org.kairosdb.core.datastore.QueryQueuingManager;
import org.kairosdb.core.http.rest.json.ErrorResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.agileclick.genorm.runtime.Pair;

import javax.inject.Inject;
import javax.ws.rs.*;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

import java.util.ArrayList;

import static java.util.Objects.requireNonNull;
import static org.kairosdb.core.http.rest.MetricsResource.setHeaders;

@Path("api/v1/admin")
public class AdminResource
{
	private static final Logger logger = LoggerFactory.getLogger(AdminResource.class);

	private final QueryQueuingManager m_queuingManager;

	@Inject
	public AdminResource(QueryQueuingManager queuingManager)
	{
		this.m_queuingManager = requireNonNull(queuingManager, "queuingManager cannot be null.");
	}

	@GET
	@Produces(MediaType.APPLICATION_JSON + "; charset=UTF-8")
	@Path("/runningqueries")
	public Response listRunningQueries()
	{
		try
		{
			int queriesWaitingCount = m_queuingManager.getQueryWaitingCount();
			ArrayList<Pair<String, QueryMetric>> runningQueries = m_queuingManager.getRunningQueries();
			JsonArray queryInfo = new JsonArray();

			JsonObject responseJson = new JsonObject();
			for (Pair<String, QueryMetric> query : runningQueries)
			{
				JsonObject queryJson = new JsonObject();
				String queryHash = query.getFirst();
				QueryMetric queryMetric = query.getSecond();
				queryJson.addProperty("query hash", queryHash);
				queryJson.addProperty("metric name", queryMetric.getName());
				queryJson.add("query JSON", queryMetric.getJsonObj());

				queryInfo.add(queryJson);
			}
			responseJson.add("queries", queryInfo);
			responseJson.addProperty("queries waiting", queriesWaitingCount);

			logger.debug("Listing running queries.");
			Response.ResponseBuilder responseBuilder = Response.status(Response.Status.OK).entity(responseJson.toString());
			setHeaders(responseBuilder);
			return responseBuilder.build();

		}
		catch (Exception e)
		{
			logger.error("Failed to get running queries.", e);
			return setHeaders(Response.status(Response.Status.INTERNAL_SERVER_ERROR).entity(new ErrorResponse(e.getMessage()))).build();
		}
	}

	@GET
	@Produces(MediaType.APPLICATION_JSON + "; charset=UTF-8")
	@Path("/killquery/{queryHash}")
	public Response killQueryByHash(@PathParam("queryHash") String queryHash)
	{
		try
		{
			m_queuingManager.killQuery(queryHash);
			logger.info("Killed query by hash: " + queryHash);
			return setHeaders(Response.status(Response.Status.NO_CONTENT)).build();
		}
		catch (Exception e)
		{
			logger.error("Failed to kill query by hash: " + queryHash, e);
			return setHeaders(Response.status(Response.Status.INTERNAL_SERVER_ERROR).entity(new ErrorResponse(e.getMessage()))).build();
		}
	}

}
