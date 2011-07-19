//
//  OTPAuthURLTest.m
//
//  Copyright 2011 Google Inc.
//
//  Licensed under the Apache License, Version 2.0 (the "License"); you may not
//  use this file except in compliance with the License.  You may obtain a copy
//  of the License at
//
//  http://www.apache.org/licenses/LICENSE-2.0
//
//  Unless required by applicable law or agreed to in writing, software
//  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
//  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.  See the
//  License for the specific language governing permissions and limitations under
//  the License.
//

#import "GTMSenTestCase.h"

#import "GTMStringEncoding.h"
#import "GTMNSDictionary+URLArguments.h"
#import "GTMNSString+URLArguments.h"
#import "HOTPGenerator.h"
#import "OTPAuthURL.h"
#import "TOTPGenerator.h"

@interface OTPAuthURL ()

@property(readonly,retain,nonatomic) id generator;

+ (OTPAuthURL *)authURLWithKeychainDictionary:(NSDictionary *)dict;
- (id)initWithOTPGenerator:(id)generator name:(NSString *)name;

@end

static NSString *const kOTPAuthScheme = @"otpauth";

// These are keys in the otpauth:// query string.
static NSString *const kQueryAlgorithmKey = @"algorithm";
static NSString *const kQuerySecretKey = @"secret";
static NSString *const kQueryCounterKey = @"counter";
static NSString *const kQueryDigitsKey = @"digits";
static NSString *const kQueryPeriodKey = @"period";

static NSString *const kValidType = @"totp";
static NSString *const kValidLabel = @"Léon";
static NSString *const kValidAlgorithm = @"SHA256";
static const unsigned char kValidSecret[] =
    { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
      0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
static NSString *const  kValidBase32Secret = @"AAAQEAYEAUDAOCAJBIFQYDIOB4";
static const unsigned long long kValidCounter = 18446744073709551615ULL;
static NSString *const kValidCounterString = @"18446744073709551615";
static const NSUInteger kValidDigits = 8;
static NSString *const kValidDigitsString = @"8";
static const NSTimeInterval kValidPeriod = 45;
static NSString *const kValidPeriodString = @"45";

static NSString *const kValidTOTPURLWithoutSecret =
    @"otpauth://totp/L%C3%A9on?algorithm=SHA256&digits=8&period=45";

static NSString *const kValidTOTPURL =
    @"otpauth://totp/L%C3%A9on?algorithm=SHA256&digits=8&period=45"
    @"&secret=AAAQEAYEAUDAOCAJBIFQYDIOB4";

static NSString *const kValidHOTPURL =
    @"otpauth://hotp/L%C3%A9on?algorithm=SHA256&digits=8"
    @"&counter=18446744073709551615"
    @"&secret=AAAQEAYEAUDAOCAJBIFQYDIOB4";

@interface OTPAuthURLTest : GTMTestCase
- (void)testInitWithKeychainDictionary;
- (void)testInitWithTOTPURL;
- (void)testInitWithHOTPURL;
- (void)testInitWithInvalidURLS;
- (void)testInitWithOTPGeneratorLabel;
- (void)testURL;

@end

@implementation OTPAuthURLTest

- (void)testInitWithKeychainDictionary {
  NSData *secret = [NSData dataWithBytes:kValidSecret
                                  length:sizeof(kValidSecret)];
  NSData *urlData = [kValidTOTPURLWithoutSecret
                     dataUsingEncoding:NSUTF8StringEncoding];

  OTPAuthURL *url = [OTPAuthURL authURLWithKeychainDictionary:
                     [NSDictionary dictionaryWithObjectsAndKeys:
                      urlData, (id)kSecAttrGeneric,
                      secret, (id)kSecValueData,
                      nil]];

  STAssertEqualObjects([url name], kValidLabel, @"Léon");

  TOTPGenerator *generator = [url generator];
  STAssertEqualObjects([generator secret], secret, @"");
  STAssertEqualObjects([generator algorithm], kValidAlgorithm, @"");
  STAssertEquals([generator period], kValidPeriod, @"");
  STAssertEquals([generator digits], kValidDigits, @"");

  STAssertFalse([url isInKeychain], @"");
}

- (void)testInitWithTOTPURL {
  NSData *secret = [NSData dataWithBytes:kValidSecret
                                  length:sizeof(kValidSecret)];

  OTPAuthURL *url
    = [OTPAuthURL authURLWithURL:[NSURL URLWithString:kValidTOTPURL]
                          secret:nil];

  STAssertEqualObjects([url name], kValidLabel, @"Léon");

  TOTPGenerator *generator = [url generator];
  STAssertEqualObjects([generator secret], secret, @"");
  STAssertEqualObjects([generator algorithm], kValidAlgorithm, @"");
  STAssertEquals([generator period], kValidPeriod, @"");
  STAssertEquals([generator digits], kValidDigits, @"");
}

- (void)testInitWithHOTPURL {
  NSData *secret = [NSData dataWithBytes:kValidSecret
                                  length:sizeof(kValidSecret)];

  OTPAuthURL *url
    = [OTPAuthURL authURLWithURL:[NSURL URLWithString:kValidHOTPURL]
                          secret:nil];

  STAssertEqualObjects([url name], kValidLabel, @"Léon");

  HOTPGenerator *generator = [url generator];
  STAssertEqualObjects([generator secret], secret, @"");
  STAssertEqualObjects([generator algorithm], kValidAlgorithm, @"");
  STAssertEquals([generator counter], kValidCounter, @"");
  STAssertEquals([generator digits], kValidDigits, @"");
}

- (void)testInitWithInvalidURLS {
  NSArray *badUrls = [NSArray arrayWithObjects:
      // invalid scheme
      @"http://foo",
      // invalid type
      @"otpauth://foo",
      // missing secret
      @"otpauth://totp/bar",
      // invalid period
      @"otpauth://totp/bar?secret=AAAQEAYEAUDAOCAJBIFQYDIOB4&period=0",
      // missing counter
      @"otpauth://hotp/bar?secret=AAAQEAYEAUDAOCAJBIFQYDIOB4",
      // invalid algorithm
      @"otpauth://totp/bar?secret=AAAQEAYEAUDAOCAJBIFQYDIOB4&algorithm=RC4",
      // invalid digits
      @"otpauth://totp/bar?secret=AAAQEAYEAUDAOCAJBIFQYDIOB4&digits=2",
      nil];

  for (NSString *badUrl in badUrls) {
    OTPAuthURL *url
      = [OTPAuthURL authURLWithURL:[NSURL URLWithString:badUrl] secret:nil];
    STAssertNil(url, @"invalid url (%@) generated %@", badUrl, url);
  }
}

- (void)testInitWithOTPGeneratorLabel {
  TOTPGenerator *generator
    = [[[TOTPGenerator alloc] initWithSecret:[NSData data]
                                   algorithm:[OTPGenerator defaultAlgorithm]
                                      digits:[OTPGenerator defaultDigits]]
       autorelease];

  OTPAuthURL *url = [[[OTPAuthURL alloc] initWithOTPGenerator:generator
                                                         name:kValidLabel]
                     autorelease];

  STAssertEquals([url generator], generator, @"");
  STAssertEqualObjects([url name], kValidLabel, @"");
  STAssertFalse([url isInKeychain], @"");
}

- (void)testURL {
  OTPAuthURL *url
    = [OTPAuthURL authURLWithURL:[NSURL URLWithString:kValidTOTPURL]
                          secret:nil];

  STAssertEqualObjects([[url url] scheme], kOTPAuthScheme, @"");
  STAssertEqualObjects([[url url] host], kValidType, @"");
  STAssertEqualObjects([[[url url] path] substringFromIndex:1],
                       kValidLabel,
                       @"");
  NSDictionary *result =
      [NSDictionary dictionaryWithObjectsAndKeys:
       kValidAlgorithm, kQueryAlgorithmKey,
       kValidDigitsString, kQueryDigitsKey,
       kValidPeriodString, kQueryPeriodKey,
       nil];
  STAssertEqualObjects([NSDictionary gtm_dictionaryWithHttpArgumentsString:
                        [[url url] query]],
                       result,
                       @"");

  OTPAuthURL *url2
    = [OTPAuthURL authURLWithURL:[NSURL URLWithString:kValidHOTPURL]
                          secret:nil];

  NSDictionary *resultForHOTP =
      [NSDictionary dictionaryWithObjectsAndKeys:
       kValidAlgorithm, kQueryAlgorithmKey,
       kValidDigitsString, kQueryDigitsKey,
       kValidCounterString, kQueryCounterKey,
       nil];
  STAssertEqualObjects([NSDictionary gtm_dictionaryWithHttpArgumentsString:
                        [[url2 url] query]],
                       resultForHOTP,
                       @"");
}

- (void)testDuplicateURLs {
  NSURL *url = [NSURL URLWithString:kValidTOTPURL];
  OTPAuthURL *authURL1 = [OTPAuthURL authURLWithURL:url secret:nil];
  OTPAuthURL *authURL2 = [OTPAuthURL authURLWithURL:url secret:nil];
  STAssertTrue([authURL1 saveToKeychain], nil);
  STAssertTrue([authURL2 saveToKeychain], nil);
  STAssertTrue([authURL1 removeFromKeychain],
               @"Your keychain may now have an invalid entry %@", authURL1);
  STAssertTrue([authURL2 removeFromKeychain],
               @"Your keychain may now have an invalid entry %@", authURL2);
}

@end
