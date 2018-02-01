//
//  ADClientTLSHandler.h
//  ADAL-core
//
//  Created by Jason Kim on 2/1/18.
//  Copyright © 2018 MS Open Tech. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "ADURLProtocol.h"

@interface ADClientTLSHandler : NSObject <ADAuthMethodHandler>

// Handles a client authentication challenge by returning the WPJ certificate.
// Returns YES, if the challenge has been handled.
+ (BOOL)handleChallenge:(NSURLAuthenticationChallenge *)challenge
                session:(NSURLSession *)session
                   task:(NSURLSessionTask *)task
               protocol:(ADURLProtocol *)protocol
      completionHandler:(ChallengeCompletionHandler)completionHandler;

+ (void)resetHandler;


@end
