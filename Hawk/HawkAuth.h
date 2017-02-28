//
//  HawkAuth.h
//  Hawk
//
//  Created by Jesse Stuart on 8/9/13.
//  nonatomicright (c) 2013 Tent. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "HawkCredentials.h"
#import "HawkError.h"

typedef NS_ENUM(NSUInteger, HawkAuthType) {
        HawkAuthTypeHeader,
        HawkAuthTypeResponse,
        HawkAuthTypeBewit
};

const static NSString *kHawkHeaderVersion = @"1";

@interface HawkAuth : NSObject

#pragma mark - Fluent API-style Builder Methods

+ (instancetype)withCredentials:(HawkCredentials *)credentials;
- (instancetype)withMethod:(NSString *)method;
- (instancetype)withURL:(NSURL *)url;
- (instancetype)withTimestamp:(NSDate *)timestamp;

/*
 Generates an opaque, unique nonce.
 Overrides existing nonce, if any.
 */
- (instancetype)generateNonce;

/*
 Set nonce using a value of your choice.
 Overrides existing nonce, if any.
 */
- (instancetype)withNonce:(NSString *)nonce;

- (instancetype)withExt:(NSString *)ext;
- (instancetype)withApp:(NSString *)applicationID;
- (instancetype)withDlg:(NSString *)dlg;
- (instancetype)withPayload:(NSString *)payload;
- (instancetype)withContentType:(NSString *)contentType;

@property (nonatomic, readonly) HawkCredentials *credentials;

@property (nonatomic, readonly) NSString *method;
@property (nonatomic, readonly) NSURL *url;

@property (nonatomic, readonly) NSDate *timestamp;
@property (nonatomic, readonly) NSString *nonce;
@property (nonatomic, readonly) NSString *ext;

@property (nonatomic, readonly) NSString *app;
@property (nonatomic, readonly) NSString *dlg;

@property (nonatomic, readonly) NSString *payload;
@property (nonatomic, readonly) NSString *contentType;

#pragma mark -

// Returns an instance of CryptoProxy using self.credentials.algorithm
- (CryptoProxy *)cryptoProxy;

// Returns input string for hmac functions
- (NSString *)normalizedStringWithType:(HawkAuthType)type;

// Returns input string for hash digest function
- (NSString *)normalizedPayloadString;

// Sets and returns hash property
- (NSString *)payloadHash;

// Sets and returns hmac property
- (NSString *)hmacWithType:(HawkAuthType)type;

// Returns hmac for timestamp skew header
- (NSString *)timestampSkewHmac;

- (NSString *)bewit;

#pragma mark -

/*
 Key and value for authorization header.
 @return 'Authorization: Hawk id='<id>', <etc...>`
 */
- (NSString *)requestHeader;

/*
 Returns only value for authorization header.
 @return 'Hawk id='<id>', <etc...>`
 */
- (NSString *)requestHeaderValue;

- (NSString *)responseHeader;
- (NSString *)responseHeaderValue;
- (NSString *)timestampSkewHeader;

#pragma mark -

// Parses header attributes
- (NSDictionary *)parseAuthorizationHeader:(NSString *)header;

/*
 Returns an instance of HawkError if invalid or nil if valid
 Sets self.credentials if valid
 self.nonce, self.timestamp, and self.app are set with values from header when valid hawk id
 credentialsLookup(<hawk id>) block should return an instance of HawkCredentials or nil
 */
- (HawkError *)validateRequestHeader:(NSString *)header
                   credentialsLookup:(HawkCredentials *(^)(NSString *hawkId))credentialsLookup;

- (HawkError *)validateResponseHeader:(NSString *)header;

- (HawkError *)validateBewit:(NSString *)bewit
           credentialsLookup:(HawkCredentials *(^)(NSString *hawkId))credentialsLookup
                  serverTime:(NSDate *)serverTime;

@end
