from typing import Any
import httpx, os, uuid
from mcp.server.fastmcp import FastMCP, Context
from starlette.applications import Starlette
from mcp.server.sse import SseServerTransport
from starlette.requests import Request
from starlette.routing import Mount, Route
from mcp.server import Server
import uvicorn
from azure.identity import DefaultAzureCredential
from azure.mgmt.apimanagement import ApiManagementClient
from azure.mgmt.apimanagement.models import AuthorizationContract, AuthorizationAccessPolicyContract, AuthorizationLoginRequestContract


# Initialize FastMCP server for Spotify API
mcp = FastMCP("Spotify")

# Environment variables
APIM_GATEWAY_URL = str(os.getenv("APIM_GATEWAY_URL"))
SUBSCRIPTION_ID = str(os.getenv("SUBSCRIPTION_ID"))
RESOURCE_GROUP_NAME = str(os.getenv("RESOURCE_GROUP_NAME"))
APIM_SERVICE_NAME = str(os.getenv("APIM_SERVICE_NAME"))
AZURE_TENANT_ID = str(os.getenv("AZURE_TENANT_ID"))
AZURE_CLIENT_ID = str(os.getenv("AZURE_CLIENT_ID"))
POST_LOGIN_REDIRECT_URL = str(os.getenv("POST_LOGIN_REDIRECT_URL"))
APIM_IDENTITY_OBJECT_ID = str(os.getenv("APIM_IDENTITY_OBJECT_ID"))
idp = "spotify"

def get_headers(ctx: Context):
    headers = {
        "Content-Type": "application/json",
        "authorizationId": f"{idp.lower()}-{str(id(ctx.session))}",
        "providerId": idp.lower() 
    }
    return headers


@mcp.tool()
async def authorize_spotify(ctx: Context) -> str:
    """Validate Credential Manager connection exists and is connected.
    
    Args:
        idp: The identity provider to authorize
    Returns:
        401: Login URL for the user to authorize the connection
        200: Connection authorized
    """
    print("Authorizing connection...")
    print(f"AZURE_TENANT_ID: {AZURE_TENANT_ID}")
    print(f"APIM Gateway URL: {APIM_GATEWAY_URL}")

    session_id = str(id(ctx.session))
    provider_id = idp.lower()
    authorization_id = f"{provider_id}-{session_id}"
    
    print(f"SessionId: {session_id}")

    print("Creating API Management client...")
    client = ApiManagementClient(
        credential=DefaultAzureCredential(),
        subscription_id=SUBSCRIPTION_ID,
    )

    try:
        response = client.authorization.get(
            resource_group_name=RESOURCE_GROUP_NAME,
            service_name=APIM_SERVICE_NAME,
            authorization_provider_id=idp,
            authorization_id=authorization_id,
        )
        if response.status == "Connected":
            print("Spotify authorization is already connected.")
            return "Connection authorized."
    except Exception as e:
        print(f"Failed to get authorization")

    print("Getting authorization provider...")
    response = client.authorization_provider.get(
        resource_group_name=RESOURCE_GROUP_NAME,
        service_name=APIM_SERVICE_NAME,
        authorization_provider_id=idp,
    )

    authContract: AuthorizationContract = AuthorizationContract(
        authorization_type="OAuth2",
        o_auth2_grant_type="AuthorizationCode"
    )

    print("Creating or updating authorization...")
    response = client.authorization.create_or_update(
        resource_group_name=RESOURCE_GROUP_NAME,
        service_name=APIM_SERVICE_NAME,
        authorization_provider_id=idp,
        authorization_id=authorization_id,
        parameters=authContract
    )

    authPolicyContract: AuthorizationAccessPolicyContract = AuthorizationAccessPolicyContract(
        tenant_id=AZURE_TENANT_ID,
        object_id=APIM_IDENTITY_OBJECT_ID
    )

    print("Creating or updating authorization access policy...")
    response = client.authorization_access_policy.create_or_update(
        resource_group_name=RESOURCE_GROUP_NAME,
        service_name=APIM_SERVICE_NAME,
        authorization_provider_id=idp,
        authorization_id=authorization_id,
        authorization_access_policy_id=str(uuid.uuid4())[:33],
        parameters=authPolicyContract
    )

    authPolicyContract: AuthorizationAccessPolicyContract = AuthorizationAccessPolicyContract(
        tenant_id=AZURE_TENANT_ID,
        object_id=AZURE_CLIENT_ID
    )

    print("Creating or updating authorization access policy...")
    response = client.authorization_access_policy.create_or_update(
        resource_group_name=RESOURCE_GROUP_NAME,
        service_name=APIM_SERVICE_NAME,
        authorization_provider_id=idp,
        authorization_id=authorization_id,
        authorization_access_policy_id=str(uuid.uuid4())[:33],
        parameters=authPolicyContract
    )

    authLoginRequestContract: AuthorizationLoginRequestContract = AuthorizationLoginRequestContract(
        post_login_redirect_url=POST_LOGIN_REDIRECT_URL
    )

    print("Getting authorization link...")
    response = client.authorization_login_links.post(
        resource_group_name=RESOURCE_GROUP_NAME,
        service_name=APIM_SERVICE_NAME,
        authorization_provider_id=idp,
        authorization_id=authorization_id,
        parameters=authLoginRequestContract
    )
    print("Login URL: ", response.login_link)
    return f"Please authorize by opening this link: {response.login_link}"



@mcp.tool()
async def get_user_playlists(ctx: Context) -> str:
    """Get user playlists
     
    Returns:
        Playlists for the user
    """
    response = httpx.get(f"{APIM_GATEWAY_URL}/me/playlists?limit=5", headers=get_headers(ctx))
    if (response.status_code == 200):
        return f"Playlists: {response.json()}"
    else:
        print(f"Unable to get playlists. Status code: {response.status_code}, Response: {response.text}")
        return f"Unable to get playlists. Status code: {response.status_code}, Response: {response.text}"

@mcp.tool()
async def get_player_queue(ctx: Context) -> str:
    """Get playback queue
     
    Returns:
        Playback queue
    """
    response = httpx.get(f"{APIM_GATEWAY_URL}/me/player/queue", headers=get_headers(ctx))
    if (response.status_code == 200):
        return f"Playback queue: {response.json()}"
    else:
        print(f"Unable to get playback queue. Status code: {response.status_code}, Response: {response.text}")
        return f"Unable to get playback queue. Status code: {response.status_code}, Response: {response.text}"

@mcp.tool()
async def get_playback_status(ctx: Context) -> str:
    """Get playback status
     
    Returns:
        Playback status
    """
    response = httpx.get(f"{APIM_GATEWAY_URL}/me/player", headers=get_headers(ctx))
    if (response.status_code == 200):
        return f"Playback status: {response.json()}"
    else:
        return f"Unable to get playback status. Status code: {response.status_code}, Response: {response.text}"

@mcp.tool()
async def start_playback(ctx: Context) -> str:
    """Start playback
     
    Returns:
        Confirmation that the playback was started
    """
    response = httpx.put(f"{APIM_GATEWAY_URL}/me/player/play", headers=get_headers(ctx))
    if (response.status_code == 200):
        return f"Playback was started!"
    else:
        return f"Unable to start playback. Status code: {response.status_code}, Response: {response.text}"

@mcp.tool()
async def pause_playback(ctx: Context) -> str:
    """Pause playback
     
    Returns:
        Confirmation of pause
    """
    response = httpx.put(f"{APIM_GATEWAY_URL}/me/player/pause", headers=get_headers(ctx))
    if (response.status_code == 200):
        return f"Playback was paused!"
    else:
        return f"Unable to pause playback. Status code: {response.status_code}, Response: {response.text}"

@mcp.tool()
async def get_my_queue(ctx: Context) -> str:
    """Get my playing queue.
     
    Returns:
        The playing queue
    """
    response = httpx.get(f"{APIM_GATEWAY_URL}/me/player/queue", headers=get_headers(ctx))
    if (response.status_code == 200):
        return f"Playing queue: {response.json()}"
    else:
        return f"Unable to get playing queue. Status code: {response.status_code}, Response: {response.text}"

@mcp.tool()
async def browse_new_releases(ctx: Context) -> str:
    """Get all new releases.
     
    Returns:
        A list of releases
    """
    response = httpx.get(f"{APIM_GATEWAY_URL}/browse/new-releases?limit=5", headers=get_headers(ctx))
    if (response.status_code == 200):
        return f"New Releases: {response.json()}"
    else:
        print(f"Unable to List Releases. Status code: {response.status_code}, Response: {response.text}")
        return f"Unable to List Releases. Status code: {response.status_code}, Response: {response.text}"

@mcp.tool()
async def search(ctx: Context, query: str) -> str:
    """Get items that match the search query.
    
    Args:
        query: search query for an artist, album, or track
    Returns:
        Seach results
    """
    response = httpx.get(f"{APIM_GATEWAY_URL}/search?q={query}&type=artist%2Calbum%2Ctrack&limit=5&market=US", headers=get_headers(ctx))
    print("SEARCH RESULT:", response)
    if (response.status_code == 200):
        return f"Search results: {response.json()}"
    else:
        return f"Unable to search. Status code: {response.status_code}, Response: {response.text}"

@mcp.tool()
async def check_authorization_status(ctx: Context) -> str:
    """Check if Spotify API authorization is successful.
    
    Returns:
        String indicating authorization status (Connected, NotConnected, or error)
    """
    print("Checking authorization status...")
    
    session_id = str(id(ctx.session))
    provider_id = idp.lower()
    authorization_id = f"{provider_id}-{session_id}"
    
    print(f"SessionId: {session_id}")

    try:
        print("Creating API Management client...")
        client = ApiManagementClient(
            credential=DefaultAzureCredential(),
            subscription_id=SUBSCRIPTION_ID,
        )
        
        response = client.authorization.get(
            resource_group_name=RESOURCE_GROUP_NAME,
            service_name=APIM_SERVICE_NAME,
            authorization_provider_id=idp,
            authorization_id=authorization_id,
        )
        
        print(f"Authorization status: {response.status}")
        
        if response.status == "Connected":
            return "Authorization status: Connected. You can use Spotify API."
        else:
            return f"Authorization status: {response.status}. Please authorize first using authorize_spotify."
            
    except Exception as e:
        print(f"Failed to check authorization status: {str(e)}")
        return f"Authorization status: Not connected. Please authorize first using authorize_spotify."

@mcp.tool()
async def check_and_repair_authorization(ctx: Context) -> str:
    """Check authorization status and attempt to fix common issues.
    
    This function diagnoses authorization issues and attempts to repair them.
    Use this when you authorized but are still seeing errors when using Spotify API.
    
    Returns:
        Detailed diagnosis and repair results
    """
    print("Diagnosing and repairing authorization...")
    
    session_id = str(id(ctx.session))
    provider_id = idp.lower()
    authorization_id = f"{provider_id}-{session_id}"
    
    print(f"SessionId: {session_id}")

    try:
        # Create API Management client
        print("Creating API Management client...")
        client = ApiManagementClient(
            credential=DefaultAzureCredential(),
            subscription_id=SUBSCRIPTION_ID,
        )
        
        # Check authorization status
        try:
            auth_response = client.authorization.get(
                resource_group_name=RESOURCE_GROUP_NAME,
                service_name=APIM_SERVICE_NAME,
                authorization_provider_id=idp,
                authorization_id=authorization_id,
            )
            
            print(f"Current authorization status: {auth_response.status}")
            
            # If already connected, test connection with a simple API call
            if auth_response.status == "Connected":
                print("Testing connection with a simple API call...")
                test_response = httpx.get(f"{APIM_GATEWAY_URL}/me", headers=get_headers(ctx))
                
                if test_response.status_code == 200:
                    return "Authorization is working correctly. If you're still having issues with specific endpoints, check if you granted the necessary permissions."
                else:
                    print(f"API test failed with status code: {test_response.status_code}, Response: {test_response.text}")
                    
                    # Attempt to refresh authorization
                    print("Attempting to refresh authorization...")
                    return await refresh_authorization(ctx, client, authorization_id)
            else:
                # Authorization exists but not connected
                print(f"Authorization exists but status is: {auth_response.status}")
                return await refresh_authorization(ctx, client, authorization_id)
                
        except Exception as e:
            print(f"Failed to retrieve authorization: {str(e)}")
            return f"Authorization not found or error occurred: {str(e)}. Please use authorize_spotify function to initiate a new authorization flow."
            
    except Exception as e:
        print(f"Failed to diagnose authorization: {str(e)}")
        return f"Failed to diagnose authorization: {str(e)}. Please check your environment variables and credentials."

async def refresh_authorization(ctx: Context, client: ApiManagementClient, authorization_id: str) -> str:
    """Helper function to refresh authorization."""
    try:
        # Delete existing authorization
        print("Deleting existing authorization...")
        client.authorization.delete(
            resource_group_name=RESOURCE_GROUP_NAME,
            service_name=APIM_SERVICE_NAME,
            authorization_provider_id=idp,
            authorization_id=authorization_id
        )
        
        print("Creating new authorization flow...")
        
        # Create new authorization
        authContract = AuthorizationContract(
            authorization_type="OAuth2",
            o_auth2_grant_type="AuthorizationCode"
        )
        
        client.authorization.create_or_update(
            resource_group_name=RESOURCE_GROUP_NAME,
            service_name=APIM_SERVICE_NAME,
            authorization_provider_id=idp,
            authorization_id=authorization_id,
            parameters=authContract
        )
        
        # Add access policies
        authPolicyContract = AuthorizationAccessPolicyContract(
            tenant_id=AZURE_TENANT_ID,
            object_id=APIM_IDENTITY_OBJECT_ID
        )
        
        client.authorization_access_policy.create_or_update(
            resource_group_name=RESOURCE_GROUP_NAME,
            service_name=APIM_SERVICE_NAME,
            authorization_provider_id=idp,
            authorization_id=authorization_id,
            authorization_access_policy_id=str(uuid.uuid4())[:33],
            parameters=authPolicyContract
        )
        
        authPolicyContract = AuthorizationAccessPolicyContract(
            tenant_id=AZURE_TENANT_ID,
            object_id=AZURE_CLIENT_ID
        )
        
        client.authorization_access_policy.create_or_update(
            resource_group_name=RESOURCE_GROUP_NAME,
            service_name=APIM_SERVICE_NAME,
            authorization_provider_id=idp,
            authorization_id=authorization_id,
            authorization_access_policy_id=str(uuid.uuid4())[:33],
            parameters=authPolicyContract
        )
        
        # Get login link
        authLoginRequestContract = AuthorizationLoginRequestContract(
            post_login_redirect_url=POST_LOGIN_REDIRECT_URL
        )
        
        response = client.authorization_login_links.post(
            resource_group_name=RESOURCE_GROUP_NAME,
            service_name=APIM_SERVICE_NAME,
            authorization_provider_id=idp,
            authorization_id=authorization_id,
            parameters=authLoginRequestContract
        )
        
        print("Login URL: ", response.login_link)
        
        return f"""
Authorization repair initiated. Please follow these steps:

1. Open this new authorization link: {response.login_link}
2. Complete the authorization process with Spotify
3. After being redirected to Bing, return here
4. Check the authorization status using check_authorization_status function
5. Then try using the Spotify API again

Important: Make sure your POST_LOGIN_REDIRECT_URL environment variable is set correctly. 
Current value: {POST_LOGIN_REDIRECT_URL}
"""
    except Exception as e:
        print(f"Failed to refresh authorization: {str(e)}")
        return f"Failed to refresh authorization: {str(e)}. Please try using authorize_spotify function directly."

@mcp.tool()
async def verify_authorization_with_test_call(ctx: Context) -> str:
    """Verify authorization by making a test call to the Spotify API.
    
    Returns:
        Result of the test API call, including detailed response or error
    """
    print("Verifying authorization with test API call...")
    
    try:
        # Make a simple call to the Spotify API to check authorization
        response = httpx.get(f"{APIM_GATEWAY_URL}/me", headers=get_headers(ctx))
        
        if response.status_code == 200:
            user_data = response.json()
            if "display_name" in user_data:
                return f"Authorization verified! Connected as user: {user_data['display_name']}"
            else:
                return f"Authorization verified, but couldn't get user display name. Full response: {user_data}"
        elif response.status_code == 401:
            return "Authorization failed: Token is expired or invalid. Please use check_and_repair_authorization function."
        else:
            return f"Authorization test failed. Status code: {response.status_code}, Response: {response.text}"
            
    except Exception as e:
        print(f"Error during authorization test: {str(e)}")
        return f"Error occurred during authorization test: {str(e)}. Check your network connection and environment variables."

@mcp.tool()
async def test_connection(ctx: Context) -> str:
    """Test the connection to the Spotify API.
    
    This function makes a simple request to the Spotify API to check
    if the authorization is working and the API is reachable.
    
    Returns:
        Result of the test, including detailed response or error
    """
    print("Testing connection to Spotify API...")
    
    try:
        response = httpx.get(f"{APIM_GATEWAY_URL}/me", headers=get_headers(ctx))
        
        if response.status_code == 200:
            return "Connection test successful! You are authorized to use the Spotify API."
        else:
            return f"Connection test failed. Status code: {response.status_code}, Response: {response.text}"
            
    except Exception as e:
        print(f"Error during connection test: {str(e)}")
        return f"Error occurred during connection test: {str(e)}. Check your network connection and environment variables."

@mcp.tool()
async def check_environment_variables(ctx: Context) -> str:
    """Check if all required environment variables are set correctly.
    
    Returns:
        Status of environment variables and suggestions for fixes
    """
    print("Checking environment variables...")
    
    required_vars = {
        "APIM_GATEWAY_URL": APIM_GATEWAY_URL,
        "SUBSCRIPTION_ID": SUBSCRIPTION_ID,
        "RESOURCE_GROUP_NAME": RESOURCE_GROUP_NAME,
        "APIM_SERVICE_NAME": APIM_SERVICE_NAME,
        "AZURE_TENANT_ID": AZURE_TENANT_ID,
        "AZURE_CLIENT_ID": AZURE_CLIENT_ID,
        "POST_LOGIN_REDIRECT_URL": POST_LOGIN_REDIRECT_URL,
        "APIM_IDENTITY_OBJECT_ID": APIM_IDENTITY_OBJECT_ID
    }
    
    missing_vars = []
    empty_vars = []
    
    for var_name, var_value in required_vars.items():
        if var_value is None:
            missing_vars.append(var_name)
        elif var_value == "":
            empty_vars.append(var_name)
    
    # Check if POST_LOGIN_REDIRECT_URL looks valid
    redirect_url_valid = True
    if POST_LOGIN_REDIRECT_URL and not (POST_LOGIN_REDIRECT_URL.startswith("http://") or POST_LOGIN_REDIRECT_URL.startswith("https://")):
        redirect_url_valid = False
    
    if not missing_vars and not empty_vars and redirect_url_valid:
        return f"""
Environment variables check passed! All required variables are set.

Current configuration:
- API Gateway URL: {APIM_GATEWAY_URL}
- Post-login Redirect URL: {POST_LOGIN_REDIRECT_URL}
- Resource Group: {RESOURCE_GROUP_NAME}
- APIM Service: {APIM_SERVICE_NAME}
"""
    else:
        issue_details = ""
        
        if missing_vars:
            issue_details += f"Missing variables: {', '.join(missing_vars)}\n"
        
        if empty_vars:
            issue_details += f"Empty variables: {', '.join(empty_vars)}\n"
        
        if not redirect_url_valid:
            issue_details += f"POST_LOGIN_REDIRECT_URL may be invalid: {POST_LOGIN_REDIRECT_URL}\n"
        
        return f"""
Environment variables check failed!

{issue_details}
To fix these issues:
1. Make sure all environment variables are properly set
2. Ensure POST_LOGIN_REDIRECT_URL is properly formatted (should begin with http:// or https://)
3. After fixing the environment variables, restart the server

These issues could explain why your authorization process isn't completing correctly.
"""

# Keep - no change needed
def create_starlette_app(mcp_server: Server, *, debug: bool = False) -> Starlette:
    """Create a Starlette application that can server the provied mcp server with SSE."""
    sse = SseServerTransport("/spotify/mcp/messages/")

    async def handle_sse(request: Request) -> None:
        print(f"handling sse")

        async with sse.connect_sse(
                request.scope,
                request.receive,
                request._send,  
        ) as (read_stream, write_stream):
            await mcp_server.run(
                read_stream,
                write_stream,
                mcp_server.create_initialization_options(),
            )

    return Starlette(
        debug=debug,
        routes=[
            Route("/spotify/mcp/sse", endpoint=handle_sse),
            Mount("/spotify/mcp/messages/", app=sse.handle_post_message),
        ],
    )


mcp_server = mcp._mcp_server  

# Bind SSE request handling to MCP server
starlette_app = create_starlette_app(mcp_server, debug=True)

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description='Run MCP SSE-based server')
    parser.add_argument('--host', default='0.0.0.0', help='Host to bind to')
    parser.add_argument('--port', type='int', default=8080, help='Port to listen on')
    args = parser.parse_args()

    uvicorn.run(starlette_app, host=args.host, port=args.port)