//
//  HawkAuth.m
//  Hawk
//
//  Created by Jesse Stuart on 8/9/13.
//  Copyright (c) 2013 Tent.is, LLC. All rights reserved.
//  Use of this source code is governed by a BSD-style license that can be found in the LICENSE file.
//

#import "HawkAuth.h"
#import "NSString+Base64.h"

@implementation HawkAuth

- (CryptoProxy *)cryptoProxy
{
        return [CryptoProxy cryptoProxyWithAlgorithm:self.credentials.algorithm];
}

- (NSString *)normalizedStringWithType:(HawkAuthType)type {
        NSMutableString *normalizedString = [NSMutableString string];
        
        NSString *hawkType;
        switch (type) {
                case HawkAuthTypeHeader:
                        hawkType = @"header";
                        break;
                case HawkAuthTypeResponse:
                        hawkType = @"response";
                        break;
                case HawkAuthTypeBewit:
                        hawkType = @"bewit";
                        break;
        }
        
        [normalizedString appendFormat:@"hawk.%@.%@\n", kHawkHeaderVersion, hawkType];
        [normalizedString appendFormat:@"%.0f\n", [self.timestamp timeIntervalSince1970]];
        [normalizedString appendFormat:@"%@\n",(self.nonce ?: @"")];
        [normalizedString appendFormat:@"%@\n",self.method];
        [normalizedString appendFormat:@"%@\n",self.url.path];
        [normalizedString appendFormat:@"%@\n", self.url.host];
        [normalizedString appendFormat:@"%@\n",self.url.port];
        [normalizedString appendFormat:@"%@\n",([self payloadHash] ?: @"")];
        [normalizedString appendFormat:@"%@\n",(self.ext ?: @"")];
        
        if (self.app) {
                [normalizedString appendFormat:@"%@\n",(self.app ?: @"")];
                [normalizedString appendFormat:@"%@\n",(self.dlg ?: @"")];
        }
        
        return normalizedString;
}

- (NSString *)normalizedPayloadString {
        NSMutableString *normalizedString = [NSMutableString string];
        
        [normalizedString appendFormat:@"hawk.%@.payload\n", kHawkHeaderVersion];
        
        NSArray *contentTypeSplit = [self.contentType componentsSeparatedByString:@";"];
        
        NSString *contentType = [[contentTypeSplit firstObject] // bounds-safe, defaults to nil
                                 stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
        [normalizedString appendFormat:@"%@\n",(contentType ?: @"")];
        
        [normalizedString appendFormat:@"%@\n",(self.payload ?: @"")];
        
        return normalizedString;
}

- (void)setMethod:(NSString *)method {
        _method = [method uppercaseString];
}

- (NSString *)payloadHash {
        return self.payload ? [self.cryptoProxy digestFromString:[self normalizedPayloadString]]
        : nil;
}

- (NSString *)hmacWithType:(HawkAuthType)type {
        return [self.cryptoProxy hmacFromString:[self normalizedStringWithType:type]
                                        withKey:self.credentials.key];
}

- (NSString *)timestampSkewHmac {
        NSTimeInterval timeStamp = [self.timestamp timeIntervalSince1970];
        NSString *normalizedString
        = [NSString stringWithFormat:@"hawk.%@.ts\n%.0f\n", kHawkHeaderVersion, timeStamp];
        
        return [self.cryptoProxy hmacFromString:normalizedString withKey:self.credentials.key];
}

- (NSString *)bewit {
        NSString *hmac = [self hmacWithType:HawkAuthTypeBewit];
        
        if (!self.ext) {
                _ext = @"";
        }
        
        NSString *normalizedString = [NSString stringWithFormat:@"%@\\%.0f\\%@\\%@", self.credentials.hawkId,
                                      [self.timestamp timeIntervalSince1970], hmac, self.ext];
        
        NSString *bewit = [[normalizedString base64EncodedString] stringByTrimmingCharactersInSet:
                           [NSCharacterSet characterSetWithCharactersInString:@"="]];
        
        bewit = [bewit stringByReplacingOccurrencesOfString:@"+" withString:@"-"];
        bewit = [bewit stringByReplacingOccurrencesOfString:@"/" withString:@"_"];
        
        return bewit;
}

#pragma mark -

- (NSString *)requestHeader {
        NSMutableString* header = [NSMutableString string];
        
        [header appendString:[NSString stringWithFormat:@"Authorization: Hawk id=\"%@\"", self.credentials.hawkId]];
        [header appendString:[NSString stringWithFormat:@", mac=\"%@\"", [self hmacWithType:HawkAuthTypeHeader]]];
        [header appendString:[NSString stringWithFormat:@", ts=\"%.0f\"", [self.timestamp timeIntervalSince1970]]];
        [header appendString:[NSString stringWithFormat:@", nonce=\"%@\"", self.nonce]];
        
        if (self.payload) {
                [header appendString:[NSString stringWithFormat:@", hash=\"%@\"", [self payloadHash]]];
        }
        
        if (self.app) {
                [header appendString:[NSString stringWithFormat:@", app=\"%@\"", self.app]];
        }
        
        if (self.ext) {
                [header appendString:[NSString stringWithFormat:@", ext=\"%@\"", self.ext]];
        }
        
        if (self.dlg) {
                [header appendString:[NSString stringWithFormat:@", dlg=\"%@\"", self.dlg]];
        }
        
        return [NSString stringWithString:header];
}

- (NSString *)responseHeader {
        NSMutableString* header = [NSMutableString string];
        
        [header appendFormat:@"Server-Authorization: Hawk mac=\"%@\"", [self hmacWithType:HawkAuthTypeResponse]];
        
        if (self.payload) {
                [header appendFormat:@", hash=\"%@\"", [self payloadHash]];
        }
        
        return [NSString stringWithString:header];
}

- (NSString *)timestampSkewHeader {
        NSString *tsm = [self timestampSkewHmac];
        NSString *header = [NSString stringWithFormat:@"WWW-Authenticate: Hawk ts=\"%.0f\", tsm=\"%@\", error=\"timestamp skew too high\"",
                            [self.timestamp timeIntervalSince1970], tsm];
        
        return header;
}

#pragma mark -

- (NSDictionary *)parseAuthorizationHeader:(NSString *)header {
        NSMutableDictionary *attributes = [[NSMutableDictionary alloc] init];
        
        // if this is not a hawk auth header, return an empty dictionary
        NSRange range = [header rangeOfString:@"Hawk "];
        if(range.location == NSNotFound) {
                return [NSDictionary dictionary];
        }
        
        NSString *attribString = [header substringFromIndex:range.location + range.length];
        NSArray *parts = [attribString componentsSeparatedByString:@","];
        
        NSString *key, *val;
        for (NSString *part in parts) {
                
                @try {
                        NSUInteger delimIndex = [part rangeOfString:@"="].location;
                        key = [part substringToIndex:delimIndex];
                        val = [part substringFromIndex:delimIndex + 1];
                        
                        key = [key stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceCharacterSet]];
                        val = [val stringByTrimmingCharactersInSet:[NSCharacterSet characterSetWithCharactersInString:@"\\\""]];
                        
                        [attributes setValue:val forKey:key];
                        
                } @catch (NSException *exception) {
                        continue; // if we get an out-of-bounds exception, try the next pair.
                }
        }
        
        return [NSDictionary dictionaryWithDictionary:attributes];
}

- (HawkError *)validateRequestHeader:(NSString *)header
                   credentialsLookup:(HawkCredentials *(^)(NSString *hawkId))credentialsLookup {
        NSDictionary *headerAttributes = [self parseAuthorizationHeader:header];
        
        // id lookup
        NSString *hawkId = [headerAttributes objectForKey:@"id"];
        
        if (!hawkId) {
                return [HawkError hawkErrorWithReason:HawkErrorUnknownId];
        }
        
        HawkCredentials *credentials = credentialsLookup(hawkId);
        
        if (!credentials) {
                return [HawkError hawkErrorWithReason:HawkErrorUnknownId];
        }
        
        // set attributes
        _credentials = credentials;
        
        _nonce = [headerAttributes objectForKey:@"nonce"];
        
        NSNumber* since1970 = [[NSNumberFormatter alloc] numberFromString:[headerAttributes objectForKey:@"ts"]];
        _timestamp = [[NSDate alloc] initWithTimeIntervalSince1970:[since1970 doubleValue]];
        
        _app = [headerAttributes objectForKey:@"app"];
        
        // validate payload hash
        NSString *hash = [headerAttributes objectForKey:@"hash"];
        if (hash) {
                NSString *expectedPayloadHash = [self payloadHash];
                
                if (![expectedPayloadHash isEqualToString:hash]) {
                        return [HawkError hawkErrorWithReason:HawkErrorInvalidPayloadHash];
                }
        }
        
        // validate hmac
        NSString *expectedMac = [self hmacWithType:HawkAuthTypeHeader];
        NSString *mac = [headerAttributes objectForKey:@"mac"];
        
        if (![expectedMac isEqualToString:mac]) {
                return [HawkError hawkErrorWithReason:HawkErrorInvalidMac];
        }
        
        // valid
        return nil;
}

- (HawkError *)validateResponseHeader:(NSString *)header {
        NSDictionary *headerAttribtues = [self parseAuthorizationHeader:header];
        
        NSString *hash = [headerAttribtues objectForKey:@"hash"];
        
        // validate payload hash
        if (hash) {
                NSString *expectedHash = [self payloadHash];
                
                if (![expectedHash isEqualToString:hash]) {
                        return [HawkError hawkErrorWithReason:HawkErrorInvalidPayloadHash];
                }
        }
        
        // validate hmac
        NSString *mac = [headerAttribtues objectForKey:@"mac"];
        
        NSString *expectedMac = [self hmacWithType:HawkAuthTypeResponse];
        
        if (![expectedMac isEqualToString:mac]) {
                return [HawkError hawkErrorWithReason:HawkErrorInvalidMac];
        }
        
        // valid
        return nil;
}

- (HawkError *)validateBewit:(NSString *)bewit
           credentialsLookup:(HawkCredentials *(^)(NSString *hawkId))credentialsLookup
                  serverTime:(NSDate *)serverTime {
        // parse bewit
        NSString *padding = [[[NSString alloc] init] stringByPaddingToLength:((4 - bewit.length) % 4) withString:@"=" startingAtIndex:0];
        
        NSString *normalizedString = [[bewit stringByAppendingString:padding] base64DecodedString];
        
        NSArray *parts = [normalizedString componentsSeparatedByString:@"\\"];
        
        // id\ts\mac\ext
        if (parts.count != 4) {
                return [HawkError hawkErrorWithReason:HawkErrorMalformedBewit];
        }
        
        // id lookup
        NSString *hawkId = [parts objectAtIndex:0];
        HawkCredentials *credentials = credentialsLookup(hawkId);
        
        if (!credentials) {
                return [HawkError hawkErrorWithReason:HawkErrorUnknownId];
        }
        
        // set attributes
        _credentials = credentials;
        
        NSNumber* since1970 = [[NSNumberFormatter alloc] numberFromString:[parts objectAtIndex:1]];
        _timestamp = [[NSDate alloc] initWithTimeIntervalSince1970:[since1970 doubleValue]];
        
        _ext = [parts objectAtIndex:3];
        
        NSString *mac = [parts objectAtIndex:2];
        
        // validate timestamp
        if ([self.timestamp timeIntervalSince1970] > [serverTime timeIntervalSince1970]) {
                return [HawkError hawkErrorWithReason:HawkErrorBewitExpired];
        }
        
        // validate hmac
        NSString *expectedMac = [self hmacWithType:HawkAuthTypeBewit];
        
        if (![expectedMac isEqualToString:mac]) {
                return [HawkError hawkErrorWithReason:HawkErrorInvalidMac];
        }
        
        // valid
        return nil;
}

@end
