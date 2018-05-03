// Copyright (c) Microsoft Corporation.
// All rights reserved.
//
// This code is licensed under the MIT License.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files(the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and / or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions :
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

#import "ADAuthenticationContext+Internal.h"
#import "ADWebRequest.h"
#import "ADWorkPlaceJoinConstants.h"
#import "ADClientMetrics.h"
#import "ADWebResponse.h"
#import "ADPkeyAuthHelper.h"
#import "ADAuthenticationSettings.h"
#import "ADWebAuthController.h"
#import "ADWebAuthController+Internal.h"
#import "ADHelpers.h"
#import "ADUserIdentifier.h"
#import "ADAuthenticationRequest.h"
#import "ADTokenCacheItem+Internal.h"
#import "ADWebAuthRequest.h"
#import "NSString+ADURLExtensions.h"
#import "MSIDDeviceId.h"
#import "MSIDAADOauth2Factory.h"
#import "MSIDAADV1Oauth2Factory.h"
#import "ADAuthenticationErrorConverter.h"
#import "MSIDRequestParameters.h"
#import "MSIDOAuth2EmbeddedWebviewController.h"
#import "MSIDWebviewAuthorization.h"
#import "MSIDWebOAuth2Response.h"

@implementation ADAuthenticationRequest (WebRequest)

- (void)executeRequest:(NSDictionary *)request_data
            completion:(MSIDTokenResponseCallback)completionBlock
{
    NSString *authority = [NSString msidIsStringNilOrBlank:_cloudAuthority] ? _context.authority : _cloudAuthority;
    NSString* urlString = [authority stringByAppendingString:MSID_OAUTH2_TOKEN_SUFFIX];
    ADWebAuthRequest* req = [[ADWebAuthRequest alloc] initWithURL:[NSURL URLWithString:urlString]
                                                          context:_requestParams];
    [req setRequestDictionary:request_data];
    [req sendRequest:^(ADAuthenticationError *error, NSDictionary *response)
     {
         if (error)
         {
             completionBlock(nil, error);
             [req invalidate];
             return;
         }

         MSIDAADV1Oauth2Factory *factory = [MSIDAADV1Oauth2Factory new];

         NSError *msidError = nil;
         MSIDTokenResponse *tokenResponse = [factory tokenResponseFromJSON:response context:nil error:&msidError];

         if (!tokenResponse)
         {
             ADAuthenticationError *adError = [ADAuthenticationErrorConverter ADAuthenticationErrorFromMSIDError:msidError];
             completionBlock(nil, adError);
         }
         else
         {
             completionBlock(tokenResponse, nil);
         }
         
         [req invalidate];
     }];
}

// Ensures that the state comes back in the response:
- (BOOL)verifyStateFromDictionary: (NSDictionary*) dictionary
{
    NSDictionary *state = [NSDictionary msidURLFormDecode:[[dictionary objectForKey:MSID_OAUTH2_STATE] msidBase64UrlDecode]];
    if (state.count != 0)
    {
        NSString *authorizationServer = [state objectForKey:@"a"];
        NSString *resource            = [state objectForKey:@"r"];
        
        if (![NSString msidIsStringNilOrBlank:authorizationServer] && ![NSString msidIsStringNilOrBlank:resource])
        {
            MSID_LOG_VERBOSE_PII(_requestParams, @"The authorization server returned the following state: %@", state);
            return YES;
        }
    }
    
    MSID_LOG_WARN(_requestParams, @"Missing or invalid state returned");
    MSID_LOG_WARN_PII(_requestParams, @"Missing or invalid state returned state: %@", state);
    return NO;
}

- (void)launchWebView:(MSIDWebUICompletionHandler)completionBlock
{
    MSIDRequestParameters *requestParams = [[MSIDRequestParameters alloc] initWithAuthority:[NSURL URLWithString:_requestParams.authority]
                                                                                redirectUri:_requestParams.redirectUri
                                                                                   clientId:_requestParams.clientId
                                                                                     target:_requestParams.resource];
    [requestParams setLoginHint:[_requestParams identifier].userId];
    [requestParams setCorrelationId:_requestParams.correlationId.UUIDString];
    [requestParams setExtraQueryParameters:_queryParams];
    [requestParams setPromptBehavior:[ADAuthenticationContext getPromptParameter:_promptBehavior]];
    [requestParams setClaims:_claims];
    MSIDAADV1Oauth2Factory *factory = [MSIDAADV1Oauth2Factory new];
    
    //MSIDOAuth2EmbeddedWebviewController *webviewController =
//    [MSIDWebviewAuthorization embeddedWebviewControllerWithRequestParameters:requestParams
//                                                                     //webview:_context.webView
//                                                                     factory:factory];
    [MSIDWebviewAuthorization startEmbeddedWebviewWebviewAuthWithRequestParameters:requestParams webview:nil factory:factory context:_requestParams completionHandler:completionBlock];
//    if (!webviewController)
//    {
//        //TODO: error out
//    }
    
    
    
    //[controller startRequestWithCompletionHandler:nil];
    
//    [[ADWebAuthController sharedInstance] start:[NSURL URLWithString:startUrl]
//                                            end:[NSURL URLWithString:[_requestParams redirectUri]]
//                                    refreshCred:_refreshTokenCredential
//#if TARGET_OS_IPHONE
//                                         parent:_context.parentController
//                                     fullScreen:[ADAuthenticationSettings sharedInstance].enableFullScreen
//#endif
//                                        webView:_context.webView
//                                        context:_requestParams
//                                     completion:completionBlock];
}

//Requests an OAuth2 code to be used for obtaining a token:
- (void)requestCode:(ADAuthorizationCodeCallback)completionBlock
{
    THROW_ON_NIL_ARGUMENT(completionBlock);
    [self ensureRequest];
    
    MSID_LOG_VERBOSE(_requestParams, @"Requesting authorization code");
    MSID_LOG_VERBOSE_PII(_requestParams, @"Requesting authorization code for resource: %@", _requestParams.resource);
    
    //NSString* startUrl = [self generateQueryStringForRequestType:MSID_OAUTH2_CODE];
    
    void(^requestCompletion)(MSIDWebOAuth2Response *response, NSError *error) = ^void(MSIDWebOAuth2Response *response, NSError *error)
    {
        
        [ADAuthenticationRequest releaseExclusionLock]; // Allow other operations that use the UI for credentials.
        //todo handle wpj response
        if (error)
        {
            completionBlock(nil, [ADAuthenticationErrorConverter ADAuthenticationErrorFromMSIDError:error]);
        }
        else
        {
            completionBlock(response.code, [ADAuthenticationErrorConverter ADAuthenticationErrorFromMSIDError:response.oauthError]);
        }
     };
    
    // If this request doesn't allow us to attempt to grab a code silently (using
    // a potential SSO cookie) then jump straight to the web view.
    if (!_allowSilent)
    {
        [self launchWebView:requestCompletion];
    }
    else
    {
        NSMutableDictionary* requestData = nil;
        requestData = [NSMutableDictionary dictionaryWithObjectsAndKeys:
                       [_requestParams clientId], MSID_OAUTH2_CLIENT_ID,
                       [_requestParams redirectUri], MSID_OAUTH2_REDIRECT_URI,
                       [_requestParams resource], MSID_OAUTH2_RESOURCE,
                       MSID_OAUTH2_CODE, MSID_OAUTH2_RESPONSE_TYPE,
                       @"1", @"nux",
                       @"none", @"prompt", nil];
        
        if (![NSString msidIsStringNilOrBlank:_requestParams.scope])
        {
            [requestData setObject:_requestParams.scope forKey:MSID_OAUTH2_SCOPE];
        }
        
        if ([_requestParams identifier] && [[_requestParams identifier] isDisplayable] && ![NSString msidIsStringNilOrBlank:[_requestParams identifier].userId])
        {
            [requestData setObject:_requestParams.identifier.userId forKey:MSID_OAUTH2_LOGIN_HINT];
        }
        
        NSURL* reqURL = [NSURL URLWithString:[_context.authority stringByAppendingString:MSID_OAUTH2_AUTHORIZE_SUFFIX]];
        ADWebAuthRequest* req = [[ADWebAuthRequest alloc] initWithURL:reqURL
                                                              context:_requestParams];
        [req setIsGetRequest:YES];
        [req setRequestDictionary:requestData];
        [req sendRequest:^(ADAuthenticationError *error, NSDictionary * parameters)
         {
             if (error && ![parameters objectForKey:@"url"]) // auth code and OAuth2 error could be in endURL
             {
                 // TODO:
                 //requestCompletion(error, nil);
                 [req invalidate];
                 return;
             }
             
             //Auth code and OAuth2 error may be passed in endURL
             NSURL* endURL = [parameters objectForKey:@"url"];
             error = nil;

             if (!endURL)
             {
                 // If the request was not silent only then launch the webview
                 if (!_silent)
                 {
                     [self launchWebView:requestCompletion];
                     return;
                 }
                 
                 // Otherwise error out
                 error = [ADAuthenticationContext errorFromDictionary:parameters errorCode:AD_ERROR_SERVER_AUTHORIZATION_CODE];
             }
             // todo:
             //requestCompletion(error, endURL);
             [req invalidate];
         }];
    }
}

@end
