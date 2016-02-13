// Copyright © Microsoft Open Technologies, Inc.
//
// All Rights Reserved
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// THIS CODE IS PROVIDED *AS IS* BASIS, WITHOUT WARRANTIES OR CONDITIONS
// OF ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING WITHOUT LIMITATION
// ANY IMPLIED WARRANTIES OR CONDITIONS OF TITLE, FITNESS FOR A
// PARTICULAR PURPOSE, MERCHANTABILITY OR NON-INFRINGEMENT.
//
// See the Apache License, Version 2.0 for the specific language
// governing permissions and limitations under the License.

#import "ADAL_Internal.h"
#import "ADAuthenticationError.h"

NSString* const ADAuthenticationErrorDomain = @"ADAuthenticationErrorDomain";
NSString* const ADInvalidArgumentDomain = @"ADAuthenticationErrorDomain";
NSString* const ADUnauthorizedResponseErrorDomain = @"ADUnauthorizedResponseErrorDomain";
NSString* const ADBrokerResponseErrorDomain = @"ADBrokerResponseErrorDomain";

NSString* const ADInvalidArgumentMessage = @"The argument '%@' is invalid. Value:%@";

NSString* const ADCancelError = @"The user has cancelled the authorization.";

@implementation ADAuthenticationError

@synthesize errorDetails = _errorDetails;
@synthesize protocolCode = _protocolCode;

- (id)init
{
    //Should not be called.
    [super doesNotRecognizeSelector:_cmd];
    return nil;
}

- (id)initWithDomain:(NSString *)domain
                code:(NSInteger)code
            userInfo:(NSDictionary *)dict
{
    (void)domain;
    (void)code;
    (void)dict;
    
    //Overrides the parent class and ensures that it throws. This one should not be called.
    [super doesNotRecognizeSelector:_cmd];
    return nil;
}

- (NSString *)description
{
    NSString* superDescription = [super description];
    
    return [NSString stringWithFormat:@"Error with code: %lu Domain: %@ ProtocolCode:%@ Details:%@. Inner error details: %@",
            (long)self.code, self.domain, self.protocolCode, self.errorDetails, superDescription];
}

- (id)initInternalWithDomain:(NSString *)domain
                        code:(NSInteger)code
                protocolCode:(NSString *)protocolCode
                errorDetails:(NSString *)details
               correlationId:(NSUUID *)correlationId
                    userInfo:(NSDictionary *)userInfo
                       quiet:(BOOL)quiet
{
    if (!domain)
    {
        domain = @"ADAL";
    }
    
    if (!quiet)
    {
        NSString* message = [NSString stringWithFormat:@"Error raised: %ld", (long)code];
        NSMutableString* info = [[NSMutableString alloc] initWithFormat:@"Domain: %@", domain];
        if (protocolCode)
        {
            [info appendFormat:@" ProtocolCode: %@", protocolCode];
        }
        if (details)
        {
            [info appendFormat:@" Details: %@", details];
        }
        AD_LOG_ERROR(message, code, correlationId, info);
        SAFE_ARC_RELEASE(info);
    }
    
    self = [super initWithDomain:domain code:code userInfo:userInfo];
    if (self)
    {
        _errorDetails = details;
        SAFE_ARC_RETAIN(_errorDetails);
        _protocolCode = protocolCode;
        SAFE_ARC_RETAIN(_protocolCode);
    }
    return self;
}

- (void)dealloc
{
    SAFE_ARC_RELEASE(_errorDetails);
    SAFE_ARC_RELEASE(_protocolCode);
    
    SAFE_ARC_SUPER_DEALLOC();
}

+ (ADAuthenticationError *)errorWithDomainInternal:(NSString *)domain
                                              code:(NSInteger)code
                                 protocolErrorCode:(NSString *)protocolCode
                                      errorDetails:(NSString *)details
                                     correlationId:(NSUUID *)correlationId
                                          userInfo:(NSDictionary *)userInfo
{
    id obj = [[self alloc] initInternalWithDomain:domain
                                             code:code
                                     protocolCode:protocolCode
                                     errorDetails:details
                                    correlationId:correlationId
                                         userInfo:userInfo
                                            quiet:NO];
    SAFE_ARC_AUTORELEASE(obj);
    return obj;
}

+ (ADAuthenticationError*)errorFromArgument:(id)argumentValue
                               argumentName:(NSString *)argumentName
                              correlationId:(NSUUID *)correlationId
{
    THROW_ON_NIL_EMPTY_ARGUMENT(argumentName);
    
    //Constructs the applicable message and return the error:
    NSString* errorMessage = [NSString stringWithFormat:ADInvalidArgumentMessage, argumentName, argumentValue];
    return [self errorWithDomainInternal:ADInvalidArgumentDomain
                                    code:AD_ERROR_INVALID_ARGUMENT
                       protocolErrorCode:nil
                            errorDetails:errorMessage
                           correlationId:correlationId
                                userInfo:nil];
}

+ (ADAuthenticationError*)invalidArgumentError:(NSString *)details
                                 correlationId:(nullable NSUUID *)correlationId
{
    return [self errorWithDomainInternal:ADInvalidArgumentDomain
                                    code:AD_ERROR_INVALID_ARGUMENT
                       protocolErrorCode:nil
                            errorDetails:details
                           correlationId:correlationId
                                userInfo:nil];
}

+ (ADAuthenticationError*)errorFromUnauthorizedResponse:(NSInteger)responseCode
                                           errorDetails:(NSString *)errorDetails
                                          correlationId:(NSUUID *)correlationId
{
    return [self errorWithDomainInternal:ADUnauthorizedResponseErrorDomain
                                    code:responseCode
                       protocolErrorCode:nil
                            errorDetails:errorDetails
                           correlationId:correlationId
                                userInfo:nil];
}

+ (ADAuthenticationError*)errorFromNSError:(NSError *)error
                              errorDetails:(NSString *)errorDetails
                             correlationId:(NSUUID *)correlationId
{
    return [self errorWithDomainInternal:error.domain
                                    code:error.code
                       protocolErrorCode:nil
                            errorDetails:errorDetails
                           correlationId:correlationId
                                userInfo:error.userInfo];
}

+ (ADAuthenticationError*)errorFromAuthenticationError:(NSInteger)code
                                          protocolCode:(NSString *)protocolCode
                                          errorDetails:(NSString *)errorDetails
                                         correlationId:(NSUUID *)correlationId
{
    return [self errorWithDomainInternal:ADAuthenticationErrorDomain
                                    code:code
                       protocolErrorCode:protocolCode
                            errorDetails:errorDetails
                           correlationId:correlationId
                                userInfo:nil];
}

+ (ADAuthenticationError*)errorQuietWithAuthenticationError:(NSInteger)code
                                               protocolCode:(NSString*)protocolCode
                                               errorDetails:(NSString*)errorDetails
{
    ADAuthenticationError* error =
    [[ADAuthenticationError alloc] initInternalWithDomain:ADAuthenticationErrorDomain
                                                     code:code
                                             protocolCode:protocolCode
                                             errorDetails:errorDetails
                                            correlationId:nil
                                                 userInfo:nil
                                                    quiet:YES];
    
    SAFE_ARC_AUTORELEASE(error);
    return error;
}

+ (ADAuthenticationError*)unexpectedInternalError:(NSString*)errorDetails
                                    correlationId:(NSUUID *)correlationId
{
    return [self errorFromAuthenticationError:AD_ERROR_UNEXPECTED
                                 protocolCode:nil
                                 errorDetails:errorDetails
                                correlationId:correlationId];
}

+ (ADAuthenticationError*)errorFromCancellation:(NSUUID *)correlationId
{
    return [ADAuthenticationError errorFromAuthenticationError:AD_ERROR_USER_CANCEL
                                                  protocolCode:nil
                                                  errorDetails:ADCancelError
                                                 correlationId:correlationId];
}


@end