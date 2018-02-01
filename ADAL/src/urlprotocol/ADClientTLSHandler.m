//
//  ADClientTLSHandler.m
//  ADAL-core
//
//  Created by Jason Kim on 2/1/18.
//  Copyright © 2018 MS Open Tech. All rights reserved.
//

#import "ADClientTLSHandler.h"
#import "ADWorkPlaceJoinUtil.h"
#import "ADRegistrationInformation.h"
#import "ADWorkPlaceJoinConstants.h"
#import <Security/Security.h>

@implementation ADClientTLSHandler

+ (void)load
{
    [ADURLProtocol registerHandler:self authMethod:NSURLAuthenticationMethodClientCertificate];
}

+ (void)resetHandler
{
}

+ (BOOL)isWPJChallenge:(NSArray *)distinguishedNames
{
    
    for (NSData *distinguishedName in distinguishedNames)
    {
        NSString *distinguishedNameString = [[[NSString alloc] initWithData:distinguishedName encoding:NSISOLatin1StringEncoding] lowercaseString];
        if ([distinguishedNameString containsString:[kADALProtectionSpaceDistinguishedName lowercaseString]])
        {
            return YES;
        }
    }
    
    return NO;
}

+ (BOOL)handleWPJChallenge:(NSURLAuthenticationChallenge *)challenge
                  protocol:(ADURLProtocol *)protocol
         completionHandler:(ChallengeCompletionHandler)completionHandler
{
    ADAuthenticationError *adError = nil;
    ADRegistrationInformation *info = [ADWorkPlaceJoinUtil getRegistrationInformation:protocol.context error:&adError];
    if (!info || ![info isWorkPlaceJoined])
    {
        MSID_LOG_INFO(protocol.context, @"Device is not workplace joined");
        MSID_LOG_INFO_PII(protocol.context, @"Device is not workplace joined. host: %@", challenge.protectionSpace.host);
        
        // In other cert auth cases we send Cancel to ensure that we continue to get
        // auth challenges, however when we do that with WPJ we don't get the subsequent
        // enroll dialog *after* the failed clientTLS challenge.
        //
        // Using DefaultHandling will result in the OS not handing back client TLS
        // challenges for another ~60 seconds, behavior that looks broken in the
        // user CBA case, but here is masked by the user having to enroll their
        // device.
        completionHandler(NSURLSessionAuthChallengePerformDefaultHandling, nil);
        return YES;
    }
    
    MSID_LOG_INFO(protocol.context, @"Responding to WPJ cert challenge");
    MSID_LOG_INFO_PII(protocol.context, @"Responding to WPJ cert challenge. host: %@", challenge.protectionSpace.host);
    
    NSURLCredential *creds = [NSURLCredential credentialWithIdentity:info.securityIdentity
                                                        certificates:@[(__bridge id)info.certificate]
                                                         persistence:NSURLCredentialPersistenceNone];
    
    completionHandler(NSURLSessionAuthChallengeUseCredential, creds);
    
    return YES;
}

+ (BOOL)handleChallenge:(NSURLAuthenticationChallenge *)challenge
                session:(NSURLSession *)session
                   task:(NSURLSessionTask *)task
               protocol:(ADURLProtocol *)protocol
      completionHandler:(ChallengeCompletionHandler)completionHandler;
{
#pragma unused(session)
#pragma unused(task)
    
    NSUUID *correlationId = protocol.context.correlationId;
    NSString *host = challenge.protectionSpace.host;
    
    MSID_LOG_INFO(protocol.context, @"Attempting to handle client certificate challenge");
    MSID_LOG_INFO_PII(protocol.context, @"Attempting to handle client certificate challenge. host: %@", host);
    
    // See if this is a challenge for the WPJ cert.
    NSArray<NSData*> *distinguishedNames = challenge.protectionSpace.distinguishedNames;
    if ([self isWPJChallenge:distinguishedNames])
    {
        return [self handleWPJChallenge:challenge protocol:protocol completionHandler:completionHandler];
    }
    
    // Otherwise check if a preferred identity is set for this host
//    SecIdentityRef identity = SecIdentityCopyPreferred((CFStringRef)host, NULL, (CFArrayRef)distinguishedNames);
//    if (identity != NULL)
//    {
//        MSID_LOG_INFO(protocol.context, @"Using preferred identity");
//    }
//    else
//    {
//        // If not prompt the user to select an identity
//        identity = [self promptUserForIdentity:distinguishedNames host:host correlationId:correlationId];
//        if (identity == NULL)
//        {
//            MSID_LOG_INFO(protocol.context, @"No identity returned from cert chooser");
//
//            // If no identity comes back then we can't handle the request
//            completionHandler(NSURLSessionAuthChallengeCancelAuthenticationChallenge, nil);
//            return YES;
//        }
//
//        // Adding a retain count to match the retain count from SecIdentityCopyPreferred
//        CFRetain(identity);
//        MSID_LOG_INFO(protocol.context, @"Using user selected certificate");
//    }
//
//    SecCertificateRef cert = NULL;
//    OSStatus status = SecIdentityCopyCertificate(identity, &cert);
//    if (status != errSecSuccess)
//    {
//        CFRelease(identity);
//        MSID_LOG_ERROR(protocol.context, @"Failed to copy certificate from identity.");
//
//        completionHandler(NSURLSessionAuthChallengeCancelAuthenticationChallenge, nil);
//        return YES;
//    }
//
//    MSID_LOG_INFO(protocol.context, @"Responding to cert auth challenge with certicate");
//    NSURLCredential *credential = [[NSURLCredential alloc] initWithIdentity:identity certificates:@[(__bridge id)cert] persistence:NSURLCredentialPersistenceNone];
//    completionHandler(NSURLSessionAuthChallengeUseCredential, credential);
//    CFRelease(cert);
//    CFRelease(identity);
    return YES;
}

@end
