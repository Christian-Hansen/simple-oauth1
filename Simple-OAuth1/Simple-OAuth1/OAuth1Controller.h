//
//  OAuth1Controller.h
//  Simple-OAuth1
//
//  Created by Christian Hansen on 02/12/12.
//  Copyright (c) 2012 Christian-Hansen. All rights reserved.
//

#import <Foundation/Foundation.h>

@class OAuth1Controller;

@protocol OAuth1ControllerDelegate <NSObject>

- (void)startedLoadingRequest:(NSURLRequest *)request oauth1Controller:(OAuth1Controller *)controller;

@end

@interface OAuth1Controller : NSObject <UIWebViewDelegate>

@property (nonatomic, strong) NSString *consumerKey;
@property (nonatomic, strong) NSString *consumerSecret;
@property (nonatomic, strong) NSString *oauthCallback;
@property (nonatomic, weak) id<OAuth1ControllerDelegate> controllerDelegate;

- (void)loginWithWebView:(UIWebView *)webWiew
              completion:(void (^)(NSDictionary *oauthTokens, NSError *error))completion;

- (void)requestAccessToken:(NSString *)oauth_token_secret
                oauthToken:(NSString *)oauth_token
             oauthVerifier:(NSString *)oauth_verifier
                completion:(void (^)(NSError *error, NSDictionary *responseParams))completion;

- (NSURLRequest *)preparedRequestForPath:(NSString *)path
                              parameters:(NSDictionary *)parameters
                              HTTPmethod:(NSString *)method
                              oauthToken:(NSString *)oauth_token
                             oauthSecret:(NSString *)oauth_token_secret;

@end
