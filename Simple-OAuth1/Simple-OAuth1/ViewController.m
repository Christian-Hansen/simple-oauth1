//
//  ViewController.m
//  Simple-OAuth1
//
//  Created by Christian Hansen on 02/12/12.
//  Copyright (c) 2012 Christian-Hansen. All rights reserved.
//

#import "ViewController.h"
#import "OAuth1Controller.h"
#import "LoginWebViewController.h"

#define MY_CONUSMER_KEY @"YOUR KEY HERE"
#define MY_CONUSMER_SECRET @"YOUR SECRET HERE"

@interface ViewController ()

@property (nonatomic, strong) OAuth1Controller *oauth1Controller;
@property (nonatomic, strong) NSString *oauthToken;
@property (nonatomic, strong) NSString *oauthTokenSecret;

@end

@implementation ViewController

- (void)viewDidLoad
{
    [super viewDidLoad];
	// Do any additional setup after loading the view, typically from a nib.
}


- (void)didReceiveMemoryWarning
{
    [super didReceiveMemoryWarning];
    // Dispose of any resources that can be recreated.
}




- (IBAction)loginTapped
{
    LoginWebViewController *loginWebViewController = [self.storyboard instantiateViewControllerWithIdentifier:@"loginWebViewController"];
    
    [self presentViewController:loginWebViewController
                       animated:YES
                     completion:^{
                         [self.oauth1Controller loginWithWebView:loginWebViewController.webView completion:^(NSDictionary *oauthTokens, NSError *error) {
                             if (!error) {
                                 // Store your tokens for authenticating your later requests, consider storing the tokens in the Keychain
                                 self.oauthToken = oauthTokens[@"oauth_token"];
                                 self.oauthTokenSecret = oauthTokens[@"oauth_token_secret"];
                                 
                                 self.accessTokenLabel.text = self.oauthToken;
                                 self.accessTokenSecretLabel.text = self.oauthTokenSecret;
                             }
                             else
                             {
                                 NSLog(@"Error authenticating: %@", error.localizedDescription);
                             }
                             [self dismissViewControllerAnimated:YES completion: ^{
                                 self.oauth1Controller = nil;
                             }];
                         }];
                     }];
}


- (IBAction)logoutTapped
{
    // Clear cookies so no session cookies can be used for the UIWebview 
    NSHTTPCookieStorage *storage = [NSHTTPCookieStorage sharedHTTPCookieStorage];
    for (NSHTTPCookie *cookie in [storage cookies]) {
        if (cookie.isSecure) {
            [storage deleteCookie:cookie];
        }
    }
    
    // Clear tokens from instance variables
    self.oauthToken = nil;
    self.oauthTokenSecret = nil;
    
    // Clear textfields
    self.accessTokenLabel.text = self.oauthToken;
    self.accessTokenSecretLabel.text = self.oauthTokenSecret;
    self.responseTextView.text = nil;
}

- (OAuth1Controller *)oauth1Controller
{
    if (_oauth1Controller == nil) {
        _oauth1Controller = [[OAuth1Controller alloc] init];
        _oauth1Controller.consumerKey = MY_CONUSMER_KEY;
        _oauth1Controller.consumerSecret = MY_CONUSMER_SECRET;
        _oauth1Controller.oauthCallback = @"http://www.goodreads.com";
    }
    return _oauth1Controller;
}


- (IBAction)testGETRequest
{
    // Goodreads GET Requests that are signed with OAuth return HTML rather than XML...
    
    // GoodReads GET Request
    NSString *path = @"user/show";
    NSDictionary *parameters = @{YOUR_GOODREADS_USERNAME : @"username", MY_CONUSMER_KEY : @"key"};
    
    
    OAuth1Controller *oauth1Controller = [[OAuth1Controller alloc] init];
    
    oauth1Controller.consumerKey = MY_CONUSMER_KEY;
    oauth1Controller.consumerSecret = MY_CONUSMER_SECRET;
    
    // Build authorized request based on path, parameters, tokens, timestamp etc.
    NSURLRequest *preparedRequest = [oauth1Controller preparedRequestForPath:path
                                                                  parameters:parameters
                                                                  HTTPmethod:@"GET"
                                                                  oauthToken:self.oauthToken
                                                                 oauthSecret:self.oauthTokenSecret];
    
    // Send the request and log response when received
    [NSURLConnection sendAsynchronousRequest:preparedRequest
                                       queue:NSOperationQueue.mainQueue
                           completionHandler:^(NSURLResponse *response, NSData *data, NSError *error) {
                               dispatch_async(dispatch_get_main_queue(), ^{
                                   self.responseTextView.text = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
                                   
                                   if (error) NSLog(@"Error in API request: %@", error.localizedDescription);
                               });
                           }];
}


- (IBAction)testPOSTRequest
{
    // Tumblr POST Request
    NSString *path = @"api/auth_user";
    
    OAuth1Controller *oauth1Controller = [[OAuth1Controller alloc] init];
    
    oauth1Controller.consumerKey = MY_CONUSMER_KEY;
    oauth1Controller.consumerSecret = MY_CONUSMER_SECRET;
    
    // Build authorized request based on path, parameters, tokens, timestamp etc.
    NSURLRequest *preparedRequest = [oauth1Controller preparedRequestForPath:path
                                                                  parameters:nil
                                                                  HTTPmethod:@"POST"
                                                                  oauthToken:self.oauthToken
                                                                 oauthSecret:self.oauthTokenSecret];
    
    // Send the request and when received show the response in the text view
    [NSURLConnection sendAsynchronousRequest:preparedRequest
                                       queue:NSOperationQueue.mainQueue
                           completionHandler:^(NSURLResponse *response, NSData *data, NSError *error) {
                               dispatch_async(dispatch_get_main_queue(), ^{
                                   self.responseTextView.text = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
                                   
                                   if (error) NSLog(@"Error in API request: %@", error.localizedDescription);
                               });
                           }];
}

@end
