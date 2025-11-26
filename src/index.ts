import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { SSEServerTransport } from "@modelcontextprotocol/sdk/server/sse.js";
import { z } from "zod";
import * as pipedrive from "pipedrive";
import * as dotenv from 'dotenv';
import Bottleneck from 'bottleneck';
import jwt from 'jsonwebtoken';
import http from 'http';

// Type for error handling
interface ErrorWithMessage {
  message: string;
}

function isErrorWithMessage(error: unknown): error is ErrorWithMessage {
  return (
    typeof error === 'object' &&
    error !== null &&
    'message' in error &&
    typeof (error as Record<string, unknown>).message === 'string'
  );
}

function getErrorMessage(error: unknown): string {
  if (isErrorWithMessage(error)) {
    return error.message;
  }
  return String(error);
}

// Load environment variables
dotenv.config();

// Check for required environment variables
if (!process.env.PIPEDRIVE_API_TOKEN) {
  console.error("ERROR: PIPEDRIVE_API_TOKEN environment variable is required");
  process.exit(1);
}

if (!process.env.PIPEDRIVE_DOMAIN) {
  console.error("ERROR: PIPEDRIVE_DOMAIN environment variable is required (e.g., 'ukkofi.pipedrive.com')");
  process.exit(1);
}

const jwtSecret = process.env.MCP_JWT_SECRET;
const jwtAlgorithm = (process.env.MCP_JWT_ALGORITHM || 'HS256') as jwt.Algorithm;
const jwtVerifyOptions = {
  algorithms: [jwtAlgorithm],
  audience: process.env.MCP_JWT_AUDIENCE,
  issuer: process.env.MCP_JWT_ISSUER,
};

if (jwtSecret) {
  const bootToken = process.env.MCP_JWT_TOKEN;
  if (!bootToken) {
    console.error("ERROR: MCP_JWT_TOKEN environment variable is required when MCP_JWT_SECRET is set");
    process.exit(1);
  }

  try {
    jwt.verify(bootToken, jwtSecret, jwtVerifyOptions);
  } catch (error) {
    console.error("ERROR: Failed to verify MCP_JWT_TOKEN", error);
    process.exit(1);
  }
}

const verifyRequestAuthentication = (req: http.IncomingMessage) => {
  if (!jwtSecret) {
    return { ok: true } as const;
  }

  const header = req.headers['authorization'];
  if (!header) {
    return { ok: false, status: 401, message: 'Missing Authorization header' } as const;
  }

  const [scheme, token] = header.split(' ');
  if (scheme !== 'Bearer' || !token) {
    return { ok: false, status: 401, message: 'Invalid Authorization header format' } as const;
  }

  try {
    jwt.verify(token, jwtSecret, jwtVerifyOptions);
    return { ok: true } as const;
  } catch (error) {
    return { ok: false, status: 401, message: 'Invalid or expired token' } as const;
  }
};

const limiter = new Bottleneck({
  minTime: Number(process.env.PIPEDRIVE_RATE_LIMIT_MIN_TIME_MS || 250),
  maxConcurrent: Number(process.env.PIPEDRIVE_RATE_LIMIT_MAX_CONCURRENT || 2),
});

const withRateLimit = <T extends object>(client: T): T => {
  return new Proxy(client, {
    get(target, prop, receiver) {
      const value = Reflect.get(target, prop, receiver);
      if (typeof value === 'function') {
        return (...args: unknown[]) => limiter.schedule(() => (value as Function).apply(target, args));
      }
      return value;
    },
  });
};

// Initialize Pipedrive API client with API token and custom domain
const apiClient = new pipedrive.ApiClient();
apiClient.basePath = `https://${process.env.PIPEDRIVE_DOMAIN}/api/v1`;
apiClient.authentications = apiClient.authentications || {};
apiClient.authentications['api_key'] = {
  type: 'apiKey',
  'in': 'query',
  name: 'api_token',
  apiKey: process.env.PIPEDRIVE_API_TOKEN
};

// Initialize Pipedrive API clients
const dealsApi = withRateLimit(new pipedrive.DealsApi(apiClient));
const personsApi = withRateLimit(new pipedrive.PersonsApi(apiClient));
const organizationsApi = withRateLimit(new pipedrive.OrganizationsApi(apiClient));
const pipelinesApi = withRateLimit(new pipedrive.PipelinesApi(apiClient));
const itemSearchApi = withRateLimit(new pipedrive.ItemSearchApi(apiClient));
const leadsApi = withRateLimit(new pipedrive.LeadsApi(apiClient));
// @ts-ignore - ActivitiesApi exists but may not be in type definitions
const activitiesApi = withRateLimit(new pipedrive.ActivitiesApi(apiClient));
// @ts-ignore - NotesApi exists but may not be in type definitions
const notesApi = withRateLimit(new pipedrive.NotesApi(apiClient));
// @ts-ignore - UsersApi exists but may not be in type definitions
const usersApi = withRateLimit(new pipedrive.UsersApi(apiClient));

// Create MCP server
const server = new McpServer({
  name: "pipedrive-mcp-server",
  version: "1.0.2",
  capabilities: {
    resources: {},
    tools: {},
    prompts: {}
  }
});

// === TOOLS ===

// Get all users (for finding owner IDs)
server.tool(
  "get-users",
  "Get all users/owners from Pipedrive to identify owner IDs for filtering deals",
  {},
  async () => {
    try {
      const response = await usersApi.getUsers();
      const users = response.data?.map((user: any) => ({
        id: user.id,
        name: user.name,
        email: user.email,
        active_flag: user.active_flag,
        role_name: user.role_name
      })) || [];

      return {
        content: [{
          type: "text",
          text: JSON.stringify({
            summary: `Found ${users.length} users in your Pipedrive account`,
            users: users
          }, null, 2)
        }]
      };
    } catch (error) {
      console.error("Error fetching users:", error);
      return {
        content: [{
          type: "text",
          text: `Error fetching users: ${getErrorMessage(error)}`
        }],
        isError: true
      };
    }
  }
);

// Get deals with flexible filtering options
server.tool(
  "get-deals",
  "Get deals from Pipedrive with flexible filtering options including search by title, date range, owner, stage, status, and more. Use 'get-users' tool first to find owner IDs.",
  {
    searchTitle: z.string().optional().describe("Search deals by title/name (partial matches supported)"),
    daysBack: z.number().optional().describe("Number of days back to fetch deals based on last activity date (default: 365)"),
    ownerId: z.number().optional().describe("Filter deals by owner/user ID (use get-users tool to find IDs)"),
    stageId: z.number().optional().describe("Filter deals by stage ID"),
    status: z.enum(['open', 'won', 'lost', 'deleted']).optional().describe("Filter deals by status (default: open)"),
    pipelineId: z.number().optional().describe("Filter deals by pipeline ID"),
    minValue: z.number().optional().describe("Minimum deal value filter"),
    maxValue: z.number().optional().describe("Maximum deal value filter"),
    limit: z.number().optional().describe("Maximum number of deals to return (default: 500)")
  },
  async ({
    searchTitle,
    daysBack = 365,
    ownerId,
    stageId,
    status = 'open',
    pipelineId,
    minValue,
    maxValue,
    limit = 500
  }) => {
    try {
      let filteredDeals: any[] = [];

      // If searching by title, use the search API first
      if (searchTitle) {
        // @ts-ignore - Bypass incorrect TypeScript definition
        const searchResponse = await dealsApi.searchDeals(searchTitle);
        filteredDeals = searchResponse.data || [];
      } else {
        // Calculate the date filter (daysBack days ago)
        const filterDate = new Date();
        filterDate.setDate(filterDate.getDate() - daysBack);
        const startDate = filterDate.toISOString().split('T')[0]; // Format as YYYY-MM-DD

        // Build API parameters (using actual Pipedrive API parameter names)
        const params: any = {
          sort: 'last_activity_date DESC',
          status: status,
          limit: limit
        };

        // Add optional filters
        if (ownerId) params.user_id = ownerId;
        if (stageId) params.stage_id = stageId;
        if (pipelineId) params.pipeline_id = pipelineId;

        // Fetch deals with filters
        // @ts-ignore - getDeals accepts parameters but types may be incomplete
        const response = await dealsApi.getDeals(params);
        filteredDeals = response.data || [];
      }

      // Apply additional client-side filtering

      // Filter by date if not searching by title
      if (!searchTitle) {
        const filterDate = new Date();
        filterDate.setDate(filterDate.getDate() - daysBack);

        filteredDeals = filteredDeals.filter((deal: any) => {
          if (!deal.last_activity_date) return false;
          const dealActivityDate = new Date(deal.last_activity_date);
          return dealActivityDate >= filterDate;
        });
      }

      // Filter by owner if specified and not already applied in API call
      if (ownerId && searchTitle) {
        filteredDeals = filteredDeals.filter((deal: any) => deal.owner_id === ownerId);
      }

      // Filter by status if specified and searching by title
      if (status && searchTitle) {
        filteredDeals = filteredDeals.filter((deal: any) => deal.status === status);
      }

      // Filter by stage if specified and not already applied in API call
      if (stageId && (searchTitle || !stageId)) {
        filteredDeals = filteredDeals.filter((deal: any) => deal.stage_id === stageId);
      }

      // Filter by pipeline if specified and not already applied in API call
      if (pipelineId && (searchTitle || !pipelineId)) {
        filteredDeals = filteredDeals.filter((deal: any) => deal.pipeline_id === pipelineId);
      }

      // Filter by value range if specified
      if (minValue !== undefined || maxValue !== undefined) {
        filteredDeals = filteredDeals.filter((deal: any) => {
          const value = parseFloat(deal.value) || 0;
          if (minValue !== undefined && value < minValue) return false;
          if (maxValue !== undefined && value > maxValue) return false;
          return true;
        });
      }

      // Apply limit
      if (filteredDeals.length > limit) {
        filteredDeals = filteredDeals.slice(0, limit);
      }

      // Build filter summary for response
      const filterSummary = {
        ...(searchTitle && { search_title: searchTitle }),
        ...(!searchTitle && { days_back: daysBack }),
        ...(!searchTitle && { filter_date: new Date(Date.now() - daysBack * 24 * 60 * 60 * 1000).toISOString().split('T')[0] }),
        status: status,
        ...(ownerId && { owner_id: ownerId }),
        ...(stageId && { stage_id: stageId }),
        ...(pipelineId && { pipeline_id: pipelineId }),
        ...(minValue !== undefined && { min_value: minValue }),
        ...(maxValue !== undefined && { max_value: maxValue }),
        total_deals_found: filteredDeals.length,
        limit_applied: limit
      };

      // Summarize deals to avoid massive responses but include notes and booking details
      const bookingFieldKey = "8f4b27fbd9dfc70d2296f23ce76987051ad7324e";
      const summarizedDeals = filteredDeals.map((deal: any) => ({
        id: deal.id,
        title: deal.title,
        value: deal.value,
        currency: deal.currency,
        status: deal.status,
        stage_name: deal.stage?.name || 'Unknown',
        pipeline_name: deal.pipeline?.name || 'Unknown',
        owner_name: deal.owner?.name || 'Unknown',
        organization_name: deal.org?.name || null,
        person_name: deal.person?.name || null,
        add_time: deal.add_time,
        last_activity_date: deal.last_activity_date,
        close_time: deal.close_time,
        won_time: deal.won_time,
        lost_time: deal.lost_time,
        notes_count: deal.notes_count || 0,
        // Include recent notes if available
        notes: deal.notes || [],
        // Include custom booking details field
        booking_details: deal[bookingFieldKey] || null
      }));

      return {
        content: [{
          type: "text",
          text: JSON.stringify({
            summary: searchTitle
              ? `Found ${filteredDeals.length} deals matching title search "${searchTitle}"`
              : `Found ${filteredDeals.length} deals matching the specified filters`,
            filters_applied: filterSummary,
            total_found: filteredDeals.length,
            deals: summarizedDeals.slice(0, 30) // Limit to 30 deals max to prevent huge responses
          }, null, 2)
        }]
      };
    } catch (error) {
      console.error("Error fetching deals:", error);
      return {
        content: [{
          type: "text",
          text: `Error fetching deals: ${getErrorMessage(error)}`
        }],
        isError: true
      };
    }
  }
);

// Get deal by ID
server.tool(
  "get-deal",
  "Get a specific deal by ID including custom fields",
  {
    dealId: z.number().describe("Pipedrive deal ID")
  },
  async ({ dealId }) => {
    try {
      // @ts-ignore - Bypass incorrect TypeScript definition, API expects just the ID
      const response = await dealsApi.getDeal(dealId);
      return {
        content: [{
          type: "text",
          text: JSON.stringify(response.data, null, 2)
        }]
      };
    } catch (error) {
      console.error(`Error fetching deal ${dealId}:`, error);
      return {
        content: [{
          type: "text",
          text: `Error fetching deal ${dealId}: ${getErrorMessage(error)}`
        }],
        isError: true
      };
    }
  }
);

// Get deal notes and custom booking details
server.tool(
  "get-deal-notes",
  "Get detailed notes and custom booking details for a specific deal",
  {
    dealId: z.number().describe("Pipedrive deal ID"),
    limit: z.number().optional().describe("Maximum number of notes to return (default: 20)")
  },
  async ({ dealId, limit = 20 }) => {
    try {
      const result: any = {
        deal_id: dealId,
        notes: [],
        booking_details: null
      };

      // Get deal details including custom fields
      try {
        // @ts-ignore - Bypass incorrect TypeScript definition
        const dealResponse = await dealsApi.getDeal(dealId);
        const deal = dealResponse.data;

        // Extract custom booking field
        const bookingFieldKey = "8f4b27fbd9dfc70d2296f23ce76987051ad7324e";
        if (deal && deal[bookingFieldKey]) {
          result.booking_details = deal[bookingFieldKey];
        }
      } catch (dealError) {
        console.error(`Error fetching deal details for ${dealId}:`, dealError);
        result.deal_error = getErrorMessage(dealError);
      }

      // Get deal notes
      try {
        // @ts-ignore - API parameters may not be fully typed
        // @ts-ignore - Bypass incorrect TypeScript definition
        const notesResponse = await notesApi.getNotes({
          deal_id: dealId,
          limit: limit
        });
        result.notes = notesResponse.data || [];
      } catch (noteError) {
        console.error(`Error fetching notes for deal ${dealId}:`, noteError);
        result.notes_error = getErrorMessage(noteError);
      }

      return {
        content: [{
          type: "text",
          text: JSON.stringify({
            summary: `Retrieved ${result.notes.length} notes and booking details for deal ${dealId}`,
            ...result
          }, null, 2)
        }]
      };
    } catch (error) {
      console.error(`Error fetching deal notes ${dealId}:`, error);
      return {
        content: [{
          type: "text",
          text: `Error fetching deal notes ${dealId}: ${getErrorMessage(error)}`
        }],
        isError: true
      };
    }
  }
);

// Search deals
server.tool(
  "search-deals",
  "Search deals by term",
  {
    term: z.string().describe("Search term for deals")
  },
  async ({ term }) => {
    try {
      // @ts-ignore - Bypass incorrect TypeScript definition
      const response = await dealsApi.searchDeals(term);
      return {
        content: [{
          type: "text",
          text: JSON.stringify(response.data, null, 2)
        }]
      };
    } catch (error) {
      console.error(`Error searching deals with term "${term}":`, error);
      return {
        content: [{
          type: "text",
          text: `Error searching deals: ${getErrorMessage(error)}`
        }],
        isError: true
      };
    }
  }
);

// Get all persons
server.tool(
  "get-persons",
  "Get all persons from Pipedrive including custom fields",
  {},
  async () => {
    try {
      const response = await personsApi.getPersons();
      return {
        content: [{
          type: "text",
          text: JSON.stringify(response.data, null, 2)
        }]
      };
    } catch (error) {
      console.error("Error fetching persons:", error);
      return {
        content: [{
          type: "text",
          text: `Error fetching persons: ${getErrorMessage(error)}`
        }],
        isError: true
      };
    }
  }
);

// Get person by ID
server.tool(
  "get-person",
  "Get a specific person by ID including custom fields",
  {
    personId: z.number().describe("Pipedrive person ID")
  },
  async ({ personId }) => {
    try {
      // @ts-ignore - Bypass incorrect TypeScript definition
      const response = await personsApi.getPerson(personId);
      return {
        content: [{
          type: "text",
          text: JSON.stringify(response.data, null, 2)
        }]
      };
    } catch (error) {
      console.error(`Error fetching person ${personId}:`, error);
      return {
        content: [{
          type: "text",
          text: `Error fetching person ${personId}: ${getErrorMessage(error)}`
        }],
        isError: true
      };
    }
  }
);

// Search persons
server.tool(
  "search-persons",
  "Search persons by term",
  {
    term: z.string().describe("Search term for persons")
  },
  async ({ term }) => {
    try {
      // @ts-ignore - Bypass incorrect TypeScript definition
      const response = await personsApi.searchPersons(term);
      return {
        content: [{
          type: "text",
          text: JSON.stringify(response.data, null, 2)
        }]
      };
    } catch (error) {
      console.error(`Error searching persons with term "${term}":`, error);
      return {
        content: [{
          type: "text",
          text: `Error searching persons: ${getErrorMessage(error)}`
        }],
        isError: true
      };
    }
  }
);

// Get all organizations
server.tool(
  "get-organizations",
  "Get all organizations from Pipedrive including custom fields",
  {},
  async () => {
    try {
      const response = await organizationsApi.getOrganizations();
      return {
        content: [{
          type: "text",
          text: JSON.stringify(response.data, null, 2)
        }]
      };
    } catch (error) {
      console.error("Error fetching organizations:", error);
      return {
        content: [{
          type: "text",
          text: `Error fetching organizations: ${getErrorMessage(error)}`
        }],
        isError: true
      };
    }
  }
);

// Get organization by ID
server.tool(
  "get-organization",
  "Get a specific organization by ID including custom fields",
  {
    organizationId: z.number().describe("Pipedrive organization ID")
  },
  async ({ organizationId }) => {
    try {
      // @ts-ignore - Bypass incorrect TypeScript definition
      const response = await organizationsApi.getOrganization(organizationId);
      return {
        content: [{
          type: "text",
          text: JSON.stringify(response.data, null, 2)
        }]
      };
    } catch (error) {
      console.error(`Error fetching organization ${organizationId}:`, error);
      return {
        content: [{
          type: "text",
          text: `Error fetching organization ${organizationId}: ${getErrorMessage(error)}`
        }],
        isError: true
      };
    }
  }
);

// Search organizations
server.tool(
  "search-organizations",
  "Search organizations by term",
  {
    term: z.string().describe("Search term for organizations")
  },
  async ({ term }) => {
    try {
      // @ts-ignore - API method exists but TypeScript definition is wrong
      const response = await (organizationsApi as any).searchOrganization({ term });
      return {
        content: [{
          type: "text",
          text: JSON.stringify(response.data, null, 2)
        }]
      };
    } catch (error) {
      console.error(`Error searching organizations with term "${term}":`, error);
      return {
        content: [{
          type: "text",
          text: `Error searching organizations: ${getErrorMessage(error)}`
        }],
        isError: true
      };
    }
  }
);

// Get all pipelines
server.tool(
  "get-pipelines",
  "Get all pipelines from Pipedrive",
  {},
  async () => {
    try {
      const response = await pipelinesApi.getPipelines();
      return {
        content: [{
          type: "text",
          text: JSON.stringify(response.data, null, 2)
        }]
      };
    } catch (error) {
      console.error("Error fetching pipelines:", error);
      return {
        content: [{
          type: "text",
          text: `Error fetching pipelines: ${getErrorMessage(error)}`
        }],
        isError: true
      };
    }
  }
);

// Get pipeline by ID
server.tool(
  "get-pipeline",
  "Get a specific pipeline by ID",
  {
    pipelineId: z.number().describe("Pipedrive pipeline ID")
  },
  async ({ pipelineId }) => {
    try {
      // @ts-ignore - Bypass incorrect TypeScript definition
      const response = await pipelinesApi.getPipeline(pipelineId);
      return {
        content: [{
          type: "text",
          text: JSON.stringify(response.data, null, 2)
        }]
      };
    } catch (error) {
      console.error(`Error fetching pipeline ${pipelineId}:`, error);
      return {
        content: [{
          type: "text",
          text: `Error fetching pipeline ${pipelineId}: ${getErrorMessage(error)}`
        }],
        isError: true
      };
    }
  }
);

// Get all stages
server.tool(
  "get-stages",
  "Get all stages from Pipedrive",
  {},
  async () => {
    try {
      // Since the stages are related to pipelines, we'll get all pipelines first
      const pipelinesResponse = await pipelinesApi.getPipelines();
      const pipelines = pipelinesResponse.data || [];
      
      // For each pipeline, fetch its stages
      const allStages = [];
      for (const pipeline of pipelines) {
        try {
          // @ts-ignore - Type definitions for getPipelineStages are incomplete
          const stagesResponse = await pipelinesApi.getPipelineStages(pipeline.id);
          const stagesData = Array.isArray(stagesResponse?.data)
            ? stagesResponse.data
            : [];

          if (stagesData.length > 0) {
            const pipelineStages = stagesData.map((stage: any) => ({
              ...stage,
              pipeline_name: pipeline.name
            }));
            allStages.push(...pipelineStages);
          }
        } catch (e) {
          console.error(`Error fetching stages for pipeline ${pipeline.id}:`, e);
        }
      }
      
      return {
        content: [{
          type: "text",
          text: JSON.stringify(allStages, null, 2)
        }]
      };
    } catch (error) {
      console.error("Error fetching stages:", error);
      return {
        content: [{
          type: "text",
          text: `Error fetching stages: ${getErrorMessage(error)}`
        }],
        isError: true
      };
    }
  }
);

// Search leads
server.tool(
  "search-leads",
  "Search leads by term",
  {
    term: z.string().describe("Search term for leads")
  },
  async ({ term }) => {
    try {
      // @ts-ignore - Bypass incorrect TypeScript definition
      const response = await leadsApi.searchLeads(term);
      return {
        content: [{
          type: "text",
          text: JSON.stringify(response.data, null, 2)
        }]
      };
    } catch (error) {
      console.error(`Error searching leads with term "${term}":`, error);
      return {
        content: [{
          type: "text",
          text: `Error searching leads: ${getErrorMessage(error)}`
        }],
        isError: true
      };
    }
  }
);

// Generic search across item types
server.tool(
  "search-all",
  "Search across all item types (deals, persons, organizations, etc.)",
  {
    term: z.string().describe("Search term"),
    itemTypes: z.string().optional().describe("Comma-separated list of item types to search (deal,person,organization,product,file,activity,lead)")
  },
  async ({ term, itemTypes }) => {
    try {
      const itemType = itemTypes; // Just rename the parameter
      const response = await itemSearchApi.searchItem({ 
        term,
        itemType 
      });
      return {
        content: [{
          type: "text",
          text: JSON.stringify(response.data, null, 2)
        }]
      };
    } catch (error) {
      console.error(`Error performing search with term "${term}":`, error);
      return {
        content: [{
          type: "text",
          text: `Error performing search: ${getErrorMessage(error)}`
        }],
        isError: true
      };
    }
  }
);

// === WRITE OPERATIONS ===

// Create a new deal
server.tool(
  "create-deal",
  "Create a new deal in Pipedrive",
  {
    title: z.string().describe("Deal title (required)"),
    stageId: z.number().optional().describe("Pipeline stage ID (use get-stages to find IDs)"),
    ownerId: z.number().optional().describe("Owner/user ID (use get-users to find IDs)"),
    value: z.number().optional().describe("Deal value/amount"),
    currency: z.string().optional().describe("Currency code (e.g., 'USD', 'EUR')"),
    personId: z.number().optional().describe("Associated person ID"),
    organizationId: z.number().optional().describe("Associated organization ID"),
    status: z.enum(['open', 'won', 'lost']).optional().describe("Deal status (default: open)"),
    expectedCloseDate: z.string().optional().describe("Expected close date (YYYY-MM-DD format)")
  },
  async ({ title, stageId, ownerId, value, currency, personId, organizationId, status, expectedCloseDate }) => {
    try {
      const dealData: any = { title };
      if (stageId) dealData.stage_id = stageId;
      if (ownerId) dealData.user_id = ownerId;
      if (value !== undefined) dealData.value = value;
      if (currency) dealData.currency = currency;
      if (personId) dealData.person_id = personId;
      if (organizationId) dealData.org_id = organizationId;
      if (status) dealData.status = status;
      if (expectedCloseDate) dealData.expected_close_date = expectedCloseDate;

      // @ts-ignore - API method exists
      const response = await dealsApi.addDeal(dealData);
      return {
        content: [{
          type: "text",
          text: JSON.stringify({
            success: true,
            message: `Deal "${title}" created successfully`,
            deal: response.data
          }, null, 2)
        }]
      };
    } catch (error) {
      console.error("Error creating deal:", error);
      return {
        content: [{
          type: "text",
          text: `Error creating deal: ${getErrorMessage(error)}`
        }],
        isError: true
      };
    }
  }
);

// Update an existing deal
server.tool(
  "update-deal",
  "Update an existing deal's properties",
  {
    dealId: z.number().describe("Deal ID to update"),
    title: z.string().optional().describe("New deal title"),
    value: z.number().optional().describe("New deal value"),
    currency: z.string().optional().describe("Currency code"),
    status: z.enum(['open', 'won', 'lost']).optional().describe("Deal status"),
    personId: z.number().optional().describe("Associated person ID"),
    organizationId: z.number().optional().describe("Associated organization ID"),
    expectedCloseDate: z.string().optional().describe("Expected close date (YYYY-MM-DD)")
  },
  async ({ dealId, title, value, currency, status, personId, organizationId, expectedCloseDate }) => {
    try {
      const updateData: any = {};
      if (title) updateData.title = title;
      if (value !== undefined) updateData.value = value;
      if (currency) updateData.currency = currency;
      if (status) updateData.status = status;
      if (personId) updateData.person_id = personId;
      if (organizationId) updateData.org_id = organizationId;
      if (expectedCloseDate) updateData.expected_close_date = expectedCloseDate;

      // @ts-ignore - API method exists
      const response = await dealsApi.updateDeal(dealId, updateData);
      return {
        content: [{
          type: "text",
          text: JSON.stringify({
            success: true,
            message: `Deal ${dealId} updated successfully`,
            deal: response.data
          }, null, 2)
        }]
      };
    } catch (error) {
      console.error(`Error updating deal ${dealId}:`, error);
      return {
        content: [{
          type: "text",
          text: `Error updating deal ${dealId}: ${getErrorMessage(error)}`
        }],
        isError: true
      };
    }
  }
);

// Update deal stage (move deal in pipeline)
server.tool(
  "update-deal-stage",
  "Move a deal to a different stage in the pipeline",
  {
    dealId: z.number().describe("Deal ID to move"),
    stageId: z.number().describe("Target stage ID (use get-stages to find IDs)")
  },
  async ({ dealId, stageId }) => {
    try {
      // @ts-ignore - API method exists
      const response = await dealsApi.updateDeal(dealId, { stage_id: stageId });
      return {
        content: [{
          type: "text",
          text: JSON.stringify({
            success: true,
            message: `Deal ${dealId} moved to stage ${stageId}`,
            deal: response.data
          }, null, 2)
        }]
      };
    } catch (error) {
      console.error(`Error moving deal ${dealId} to stage ${stageId}:`, error);
      return {
        content: [{
          type: "text",
          text: `Error moving deal: ${getErrorMessage(error)}`
        }],
        isError: true
      };
    }
  }
);

// Get activity types
server.tool(
  "get-activity-types",
  "Get all available activity types in Pipedrive",
  {},
  async () => {
    try {
      // @ts-ignore - ActivityTypesApi exists
      const activityTypesApi = withRateLimit(new pipedrive.ActivityTypesApi(apiClient));
      // @ts-ignore - API method exists
      const response = await activityTypesApi.getActivityTypes();
      const types = response.data?.map((t: any) => ({
        id: t.id,
        name: t.name,
        key_string: t.key_string,
        icon_key: t.icon_key,
        active: t.active_flag
      })) || [];

      return {
        content: [{
          type: "text",
          text: JSON.stringify({
            summary: `Found ${types.length} activity types`,
            activity_types: types
          }, null, 2)
        }]
      };
    } catch (error) {
      console.error("Error fetching activity types:", error);
      return {
        content: [{
          type: "text",
          text: `Error fetching activity types: ${getErrorMessage(error)}`
        }],
        isError: true
      };
    }
  }
);

// Get activities for a deal
server.tool(
  "get-deal-activities",
  "Get all activities associated with a specific deal",
  {
    dealId: z.number().describe("Deal ID to get activities for"),
    done: z.enum(['0', '1']).optional().describe("Filter by done status: '0' for undone, '1' for done"),
    limit: z.number().optional().describe("Maximum number of activities to return (default: 50)")
  },
  async ({ dealId, done, limit = 50 }) => {
    try {
      const params: any = { deal_id: dealId, limit };
      if (done !== undefined) params.done = done;

      // @ts-ignore - API method exists
      const response = await activitiesApi.getActivities(params);
      const activities = response.data || [];

      return {
        content: [{
          type: "text",
          text: JSON.stringify({
            summary: `Found ${activities.length} activities for deal ${dealId}`,
            activities: activities.map((a: any) => ({
              id: a.id,
              type: a.type,
              subject: a.subject,
              done: a.done,
              due_date: a.due_date,
              due_time: a.due_time,
              duration: a.duration,
              note: a.note,
              person_name: a.person_name,
              org_name: a.org_name,
              owner_name: a.owner_name,
              add_time: a.add_time,
              marked_as_done_time: a.marked_as_done_time
            }))
          }, null, 2)
        }]
      };
    } catch (error) {
      console.error(`Error fetching activities for deal ${dealId}:`, error);
      return {
        content: [{
          type: "text",
          text: `Error fetching activities: ${getErrorMessage(error)}`
        }],
        isError: true
      };
    }
  }
);

// Create a new activity
server.tool(
  "create-activity",
  "Create a new activity (meeting, call, task, etc.) linked to a deal",
  {
    subject: z.string().describe("Activity subject/title"),
    type: z.string().describe("Activity type key (use get-activity-types to see available types, e.g., 'meeting', 'call', 'task', 'email')"),
    dealId: z.number().optional().describe("Deal ID to link the activity to"),
    personId: z.number().optional().describe("Person ID to link the activity to"),
    organizationId: z.number().optional().describe("Organization ID to link the activity to"),
    dueDate: z.string().optional().describe("Due date (YYYY-MM-DD format)"),
    dueTime: z.string().optional().describe("Due time (HH:MM format, 24-hour)"),
    duration: z.string().optional().describe("Duration (HH:MM format)"),
    note: z.string().optional().describe("Activity note/description"),
    done: z.boolean().optional().describe("Mark activity as done (default: false)"),
    ownerId: z.number().optional().describe("Owner/user ID (use get-users to find IDs)")
  },
  async ({ subject, type, dealId, personId, organizationId, dueDate, dueTime, duration, note, done, ownerId }) => {
    try {
      const activityData: any = {
        subject,
        type
      };
      if (dealId) activityData.deal_id = dealId;
      if (personId) activityData.person_id = personId;
      if (organizationId) activityData.org_id = organizationId;
      if (dueDate) activityData.due_date = dueDate;
      if (dueTime) activityData.due_time = dueTime;
      if (duration) activityData.duration = duration;
      if (note) activityData.note = note;
      if (done !== undefined) activityData.done = done ? 1 : 0;
      if (ownerId) activityData.user_id = ownerId;

      // @ts-ignore - API method exists
      const response = await activitiesApi.addActivity(activityData);
      return {
        content: [{
          type: "text",
          text: JSON.stringify({
            success: true,
            message: `Activity "${subject}" created successfully`,
            activity: response.data
          }, null, 2)
        }]
      };
    } catch (error) {
      console.error("Error creating activity:", error);
      return {
        content: [{
          type: "text",
          text: `Error creating activity: ${getErrorMessage(error)}`
        }],
        isError: true
      };
    }
  }
);

// Update an existing activity
server.tool(
  "update-activity",
  "Update an existing activity's properties",
  {
    activityId: z.number().describe("Activity ID to update"),
    subject: z.string().optional().describe("New subject/title"),
    type: z.string().optional().describe("Activity type key"),
    dueDate: z.string().optional().describe("Due date (YYYY-MM-DD format)"),
    dueTime: z.string().optional().describe("Due time (HH:MM format)"),
    duration: z.string().optional().describe("Duration (HH:MM format)"),
    note: z.string().optional().describe("Activity note/description"),
    done: z.boolean().optional().describe("Mark activity as done/undone"),
    ownerId: z.number().optional().describe("New owner/user ID")
  },
  async ({ activityId, subject, type, dueDate, dueTime, duration, note, done, ownerId }) => {
    try {
      const updateData: any = {};
      if (subject) updateData.subject = subject;
      if (type) updateData.type = type;
      if (dueDate) updateData.due_date = dueDate;
      if (dueTime) updateData.due_time = dueTime;
      if (duration) updateData.duration = duration;
      if (note) updateData.note = note;
      if (done !== undefined) updateData.done = done ? 1 : 0;
      if (ownerId) updateData.user_id = ownerId;

      // @ts-ignore - API method exists
      const response = await activitiesApi.updateActivity(activityId, updateData);
      return {
        content: [{
          type: "text",
          text: JSON.stringify({
            success: true,
            message: `Activity ${activityId} updated successfully`,
            activity: response.data
          }, null, 2)
        }]
      };
    } catch (error) {
      console.error(`Error updating activity ${activityId}:`, error);
      return {
        content: [{
          type: "text",
          text: `Error updating activity: ${getErrorMessage(error)}`
        }],
        isError: true
      };
    }
  }
);

// Mark activity as done
server.tool(
  "mark-activity-done",
  "Mark an activity as completed",
  {
    activityId: z.number().describe("Activity ID to mark as done")
  },
  async ({ activityId }) => {
    try {
      // @ts-ignore - API method exists
      const response = await activitiesApi.updateActivity(activityId, { done: 1 });
      return {
        content: [{
          type: "text",
          text: JSON.stringify({
            success: true,
            message: `Activity ${activityId} marked as done`,
            activity: response.data
          }, null, 2)
        }]
      };
    } catch (error) {
      console.error(`Error marking activity ${activityId} as done:`, error);
      return {
        content: [{
          type: "text",
          text: `Error marking activity as done: ${getErrorMessage(error)}`
        }],
        isError: true
      };
    }
  }
);

// Create a new person
server.tool(
  "create-person",
  "Create a new person/contact in Pipedrive",
  {
    name: z.string().describe("Person's name (required)"),
    email: z.string().optional().describe("Email address"),
    phone: z.string().optional().describe("Phone number"),
    organizationId: z.number().optional().describe("Organization ID to associate with"),
    ownerId: z.number().optional().describe("Owner/user ID")
  },
  async ({ name, email, phone, organizationId, ownerId }) => {
    try {
      const personData: any = { name };
      if (email) personData.email = [{ value: email, primary: true, label: 'work' }];
      if (phone) personData.phone = [{ value: phone, primary: true, label: 'work' }];
      if (organizationId) personData.org_id = organizationId;
      if (ownerId) personData.owner_id = ownerId;

      // @ts-ignore - API method exists
      const response = await personsApi.addPerson(personData);
      return {
        content: [{
          type: "text",
          text: JSON.stringify({
            success: true,
            message: `Person "${name}" created successfully`,
            person: response.data
          }, null, 2)
        }]
      };
    } catch (error) {
      console.error("Error creating person:", error);
      return {
        content: [{
          type: "text",
          text: `Error creating person: ${getErrorMessage(error)}`
        }],
        isError: true
      };
    }
  }
);

// Create a new organization
server.tool(
  "create-organization",
  "Create a new organization/company in Pipedrive",
  {
    name: z.string().describe("Organization name (required)"),
    address: z.string().optional().describe("Street address"),
    city: z.string().optional().describe("City"),
    state: z.string().optional().describe("State/province"),
    country: z.string().optional().describe("Country"),
    postalCode: z.string().optional().describe("Postal/ZIP code"),
    ownerId: z.number().optional().describe("Owner/user ID")
  },
  async ({ name, address, city, state, country, postalCode, ownerId }) => {
    try {
      const orgData: any = { name };
      
      // Build address string if any address components provided
      const addressParts = [address, city, state, postalCode, country].filter(Boolean);
      if (addressParts.length > 0) {
        orgData.address = addressParts.join(', ');
      }
      
      if (ownerId) orgData.owner_id = ownerId;

      // @ts-ignore - API method exists
      const response = await organizationsApi.addOrganization(orgData);
      return {
        content: [{
          type: "text",
          text: JSON.stringify({
            success: true,
            message: `Organization "${name}" created successfully`,
            organization: response.data
          }, null, 2)
        }]
      };
    } catch (error) {
      console.error("Error creating organization:", error);
      return {
        content: [{
          type: "text",
          text: `Error creating organization: ${getErrorMessage(error)}`
        }],
        isError: true
      };
    }
  }
);

// === PROMPTS ===

// Prompt for getting all deals
server.prompt(
  "list-all-deals",
  "List all deals in Pipedrive",
  {},
  () => ({
    messages: [{
      role: "user",
      content: {
        type: "text",
        text: "Please list all deals in my Pipedrive account, showing their title, value, status, and stage."
      }
    }]
  })
);

// Prompt for getting all persons
server.prompt(
  "list-all-persons",
  "List all persons in Pipedrive",
  {},
  () => ({
    messages: [{
      role: "user",
      content: {
        type: "text",
        text: "Please list all persons in my Pipedrive account, showing their name, email, phone, and organization."
      }
    }]
  })
);

// Prompt for getting all pipelines
server.prompt(
  "list-all-pipelines",
  "List all pipelines in Pipedrive",
  {},
  () => ({
    messages: [{
      role: "user",
      content: {
        type: "text",
        text: "Please list all pipelines in my Pipedrive account, showing their name and stages."
      }
    }]
  })
);

// Prompt for analyzing deals
server.prompt(
  "analyze-deals",
  "Analyze deals by stage",
  {},
  () => ({
    messages: [{
      role: "user",
      content: {
        type: "text",
        text: "Please analyze the deals in my Pipedrive account, grouping them by stage and providing total value for each stage."
      }
    }]
  })
);

// Prompt for analyzing contacts
server.prompt(
  "analyze-contacts",
  "Analyze contacts by organization",
  {},
  () => ({
    messages: [{
      role: "user",
      content: {
        type: "text",
        text: "Please analyze the persons in my Pipedrive account, grouping them by organization and providing a count for each organization."
      }
    }]
  })
);

// Prompt for analyzing leads
server.prompt(
  "analyze-leads",
  "Analyze leads by status",
  {},
  () => ({
    messages: [{
      role: "user",
      content: {
        type: "text",
        text: "Please search for all leads in my Pipedrive account and group them by status."
      }
    }]
  })
);

// Prompt for pipeline comparison
server.prompt(
  "compare-pipelines",
  "Compare different pipelines and their stages",
  {},
  () => ({
    messages: [{
      role: "user",
      content: {
        type: "text",
        text: "Please list all pipelines in my Pipedrive account and compare them by showing the stages in each pipeline."
      }
    }]
  })
);

// Prompt for finding high-value deals
server.prompt(
  "find-high-value-deals",
  "Find high-value deals",
  {},
  () => ({
    messages: [{
      role: "user",
      content: {
        type: "text",
        text: "Please identify the highest value deals in my Pipedrive account and provide information about which stage they're in and which person or organization they're associated with."
      }
    }]
  })
);

// Get transport type from environment variable (default to stdio)
const transportType = process.env.MCP_TRANSPORT || 'stdio';

if (transportType === 'sse') {
  // SSE transport - create HTTP server
  const port = parseInt(process.env.MCP_PORT || '3000', 10);
  const endpoint = process.env.MCP_ENDPOINT || '/message';

  // Store active transports by session ID
  const transports = new Map<string, SSEServerTransport>();

  const httpServer = http.createServer(async (req, res) => {
    const url = new URL(req.url!, `http://${req.headers.host}`);

    // Enable CORS
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Session-Id');

    if (req.method === 'OPTIONS') {
      res.writeHead(204);
      res.end();
      return;
    }

    if (req.method === 'GET' && url.pathname === '/sse') {
      const authResult = verifyRequestAuthentication(req);
      if (!authResult.ok) {
        res.writeHead(authResult.status, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: authResult.message }));
        return;
      }

      // Establish SSE connection
      console.error('New SSE connection request');
      const transport = new SSEServerTransport(endpoint, res);

      // Store transport by session ID
      transports.set(transport.sessionId, transport);

      transport.onclose = () => {
        console.error(`SSE connection closed: ${transport.sessionId}`);
        transports.delete(transport.sessionId);
      };

      try {
        await server.connect(transport);
        console.error(`SSE connection established: ${transport.sessionId}`);
      } catch (err) {
        console.error('Failed to establish SSE connection:', err);
        transports.delete(transport.sessionId);
      }
    } else if (req.method === 'POST' && url.pathname === endpoint) {
      const authResult = verifyRequestAuthentication(req);
      if (!authResult.ok) {
        res.writeHead(authResult.status, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: authResult.message }));
        return;
      }

      // Handle incoming message
      const sessionId = url.searchParams.get('sessionId') || req.headers['x-session-id'] as string;

      if (!sessionId) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Missing sessionId' }));
        return;
      }

      const transport = transports.get(sessionId);
      if (!transport) {
        res.writeHead(404, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Session not found' }));
        return;
      }

      req.on('error', err => {
        console.error('Error receiving POST message body:', err);
        if (!res.headersSent) {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'Invalid request body' }));
        }
      });

      try {
        await transport.handlePostMessage(req, res);
      } catch (err) {
        console.error('Error handling POST message:', err);
        if (!res.headersSent) {
          res.writeHead(500, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'Internal server error' }));
        }
      }
    } else {
      // Health check endpoint
      if (req.method === 'GET' && url.pathname === '/health') {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ status: 'ok', transport: 'sse' }));
        return;
      }

      res.writeHead(404);
      res.end('Not found');
    }
  });

  httpServer.listen(port, () => {
    console.error(`Pipedrive MCP Server (SSE) listening on port ${port}`);
    console.error(`SSE endpoint: http://localhost:${port}/sse`);
    console.error(`Message endpoint: http://localhost:${port}${endpoint}`);
  });
} else {
  // Default: stdio transport
  const transport = new StdioServerTransport();
  server.connect(transport).catch(err => {
    console.error("Failed to start MCP server:", err);
    process.exit(1);
  });

  console.error("Pipedrive MCP Server started (stdio transport)");
}
