//
//  OTPAuthURL.m
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

#import "OTPAuthURL.h"

#import <Security/Security.h>

#import "GTMNSDictionary+URLArguments.h"
#import "GTMNSString+URLArguments.h"
#import "GTMNSScanner+Unsigned.h"
#import "GTMStringEncoding.h"
#import "HOTPGenerator.h"
#import "TOTPGenerator.h"

static NSString *const kOTPAuthScheme = @"otpauth";
static NSString *const kTOTPAuthScheme = @"totp";
static NSString *const kOTPService = @"com.google.otp.authentication";
// These are keys in the otpauth:// query string.
static NSString *const kQueryAlgorithmKey = @"algorithm";
static NSString *const kQuerySecretKey = @"secret";
static NSString *const kQueryCounterKey = @"counter";
static NSString *const kQueryDigitsKey = @"digits";
static NSString *const kQueryPeriodKey = @"period";

static NSString *const kBase32Charset = @"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
static NSString *const kBase32Synonyms =
    @"AaBbCcDdEeFfGgHhIiJjKkLlMmNnOoPpQqRrSsTtUuVvWwXxYyZz";
static NSString *const kBase32Sep = @" -";

static const NSTimeInterval kTOTPDefaultSecondsBeforeChange = 5;
NSString *const OTPAuthURLWillGenerateNewOTPWarningNotification
  = @"OTPAuthURLWillGenerateNewOTPWarningNotification";
NSString *const OTPAuthURLDidGenerateNewOTPNotification
  = @"OTPAuthURLDidGenerateNewOTPNotification";
NSString *const OTPAuthURLSecondsBeforeNewOTPKey
  = @"OTPAuthURLSecondsBeforeNewOTP";

@interface OTPAuthURL ()

// re-declare readwrite
@property(readwrite, retain, nonatomic) NSData *keychainItemRef;
@property(readwrite, retain, nonatomic) OTPGenerator *generator;

// Initialize an OTPAuthURL with a dictionary of attributes from a keychain.
+ (OTPAuthURL *)authURLWithKeychainDictionary:(NSDictionary *)dict;

// Initialize an OTPAuthURL object with an otpauth:// NSURL object.
- (id)initWithOTPGenerator:(OTPGenerator *)generator
                      name:(NSString *)name;

@end

@interface TOTPAuthURL ()
@property (nonatomic, readwrite, assign) NSTimeInterval lastProgress;
@property (nonatomic, readwrite, assign) BOOL warningSent;

+ (void)totpTimer:(NSTimer *)timer;
- (id)initWithTOTPURL:(NSURL *)url;
- (id)initWithName:(NSString *)name
            secret:(NSData *)secret
         algorithm:(NSString *)algorithm
            digits:(NSUInteger)digits
             query:(NSDictionary *)query;
@end

@interface HOTPAuthURL ()
+ (BOOL)isValidCounter:(NSString *)counter;
- (id)initWithName:(NSString *)name
            secret:(NSData *)secret
         algorithm:(NSString *)algorithm
            digits:(NSUInteger)digits
             query:(NSDictionary *)query;
@property(readwrite, copy, nonatomic) NSString *otpCode;

@end

@implementation OTPAuthURL
@synthesize name = name_;
@synthesize keychainItemRef = keychainItemRef_;
@synthesize generator = generator_;
@dynamic checkCode;
@dynamic otpCode;

+ (OTPAuthURL *)authURLWithURL:(NSURL *)url
                        secret:(NSData *)secret {
  OTPAuthURL *authURL = nil;
  NSString *urlScheme = [url scheme];
  if ([urlScheme isEqualToString:kTOTPAuthScheme]) {
    // Convert totp:// into otpauth://
    authURL = [[[TOTPAuthURL alloc] initWithTOTPURL:url] autorelease];
  } else if (![urlScheme isEqualToString:kOTPAuthScheme]) {
    // Required (otpauth://)
    _GTMDevLog(@"invalid scheme: %@", [url scheme]);
  } else {
    NSString *path = [url path];
    if ([path length] > 1) {
      // Optional UTF-8 encoded human readable description (skip leading "/")
      NSString *name = [[url path] substringFromIndex:1];

      NSDictionary *query =
        [NSDictionary gtm_dictionaryWithHttpArgumentsString:[url query]];

      // Optional algorithm=(SHA1|SHA256|SHA512|MD5) defaults to SHA1
      NSString *algorithm = [query objectForKey:kQueryAlgorithmKey];
      if (!algorithm) {
        algorithm = [OTPGenerator defaultAlgorithm];
      }
      if (!secret) {
        // Required secret=Base32EncodedKey
        NSString *secretString = [query objectForKey:kQuerySecretKey];
        secret = [OTPAuthURL base32Decode:secretString];
      }
      // Optional digits=[68] defaults to 8
      NSString *digitString = [query objectForKey:kQueryDigitsKey];
      NSUInteger digits = 0;
      if (!digitString) {
        digits = [OTPGenerator defaultDigits];
      } else {
        digits = [digitString intValue];
      }

      NSString *type = [url host];
      if ([type isEqualToString:@"hotp"]) {
        authURL = [[[HOTPAuthURL alloc] initWithName:name
                                              secret:secret
                                           algorithm:algorithm
                                              digits:digits
                                               query:query] autorelease];
      } else if ([type isEqualToString:@"totp"]) {
        authURL = [[[TOTPAuthURL alloc] initWithName:name
                                              secret:secret
                                           algorithm:algorithm
                                              digits:digits
                                               query:query] autorelease];
      }
    }
  }
  return authURL;
}

+ (OTPAuthURL *)authURLWithKeychainItemRef:(NSData *)data {
  OTPAuthURL *authURL = nil;
  NSDictionary *query = [NSDictionary dictionaryWithObjectsAndKeys:
                         (id)kSecClassGenericPassword, kSecClass,
                         data, (id)kSecValuePersistentRef,
                         (id)kCFBooleanTrue, kSecReturnAttributes,
                         (id)kCFBooleanTrue, kSecReturnData,
                         nil];
  NSDictionary *result = nil;
  OSStatus status = SecItemCopyMatching((CFDictionaryRef)query,
                                        (CFTypeRef*)&result);
  if (status == noErr) {
    authURL = [self authURLWithKeychainDictionary:result];
    [authURL setKeychainItemRef:data];
  }
  return authURL;
}

+ (OTPAuthURL *)authURLWithKeychainDictionary:(NSDictionary *)dict {
  NSData *urlData = [dict objectForKey:(id)kSecAttrGeneric];
  NSData *secretData = [dict objectForKey:(id)kSecValueData];
  NSString *urlString = [[[NSString alloc] initWithData:urlData
                                               encoding:NSUTF8StringEncoding]
                         autorelease];
  NSURL *url = [NSURL URLWithString:urlString];
  return  [self authURLWithURL:url secret:secretData];
}

+ (NSData *)base32Decode:(NSString *)string {
  GTMStringEncoding *coder =
    [GTMStringEncoding stringEncodingWithString:kBase32Charset];
  [coder addDecodeSynonyms:kBase32Synonyms];
  [coder ignoreCharacters:kBase32Sep];
  return [coder decode:string];
}

+ (NSString *)encodeBase32:(NSData *)data {
  GTMStringEncoding *coder =
    [GTMStringEncoding stringEncodingWithString:kBase32Charset];
  [coder addDecodeSynonyms:kBase32Synonyms];
  [coder ignoreCharacters:kBase32Sep];
  return [coder encode:data];
}

- (id)initWithOTPGenerator:(OTPGenerator *)generator
                      name:(NSString *)name {
  if ((self = [super init])) {
    if (!generator || !name) {
      _GTMDevLog(@"Bad Args Generator:%@ Name:%@", generator, name);
      [self release];
      self = nil;
    } else {
      self.generator = generator;
      self.name = name;
    }
  }
  return self;
}

- (id)init {
  [self doesNotRecognizeSelector:_cmd];
  return nil;
}

- (void)dealloc {
  self.generator = nil;
  self.name = nil;
  self.keychainItemRef = nil;
  [super dealloc];
}

- (NSURL *)url {
  [self doesNotRecognizeSelector:_cmd];
  return nil;
}

- (BOOL)saveToKeychain {
  NSString *urlString = [[self url] absoluteString];
  NSData *urlData = [urlString dataUsingEncoding:NSUTF8StringEncoding];

  NSMutableDictionary *attributes =
   [NSMutableDictionary dictionaryWithObject:urlData
                                      forKey:(id)kSecAttrGeneric];
  OSStatus status;

  if ([self isInKeychain]) {
    NSDictionary *query = [NSDictionary dictionaryWithObjectsAndKeys:
                           (id)kSecClassGenericPassword, (id)kSecClass,
                           self.keychainItemRef, (id)kSecValuePersistentRef,
                           nil];

    status = SecItemUpdate((CFDictionaryRef)query, (CFDictionaryRef)attributes);

    _GTMDevLog(@"SecItemUpdate(%@, %@) = %ld", query, attributes, status);
  } else {
    [attributes setObject:(id)kSecClassGenericPassword forKey:(id)kSecClass];
    [attributes setObject:(id)kCFBooleanTrue forKey:(id)kSecReturnPersistentRef];
    [attributes setObject:self.generator.secret forKey:(id)kSecValueData];
    [attributes setObject:kOTPService forKey:(id)kSecAttrService];
    NSData *ref = nil;

    // The name here has to be unique or else we will get a errSecDuplicateItem
    // so if we have two items with the same name, we will just append a
    // random number on the end until we get success. We will try at max of
    // 1000 times so as to not hang in shut down.
    // We do not display this name to the user, so anything will do.
    NSString *name = self.name;
    for (int i = 0; i < 1000; i++) {
      [attributes setObject:name forKey:(id)kSecAttrAccount];
      status = SecItemAdd((CFDictionaryRef)attributes, (CFTypeRef *)&ref);
      if (status == errSecDuplicateItem) {
        name = [NSString stringWithFormat:@"%@.%ld", self.name, random()];
      } else {
        break;
      }
    }
    _GTMDevLog(@"SecItemAdd(%@, %@) = %ld", attributes, ref, status);

    if (status == noErr) {
      self.keychainItemRef = ref;
    }
  }

  return status == noErr;
}

- (BOOL)removeFromKeychain {
  if (![self isInKeychain]) {
    return NO;
  }
  NSDictionary *query = [NSDictionary dictionaryWithObjectsAndKeys:
                         (id)kSecClassGenericPassword, (id)kSecClass,
                         [self keychainItemRef], (id)kSecValuePersistentRef,
                         nil];
  OSStatus status = SecItemDelete((CFDictionaryRef)query);

  _GTMDevLog(@"SecItemDelete(%@) = %ld", query, status);

  if (status == noErr) {
    [self setKeychainItemRef:nil];
  }
  return status == noErr;
}

- (BOOL)isInKeychain {
  return self.keychainItemRef != nil;
}

- (void)generateNextOTPCode {
  _GTMDevLog(@"Called generateNextOTPCode on a non-HOTP generator");
}

- (NSString*)checkCode {
  return [self.generator generateOTPForCounter:0];
}

- (NSString *)description {
  return [NSString stringWithFormat:@"<%@ %p> Name: %@ ref: %p checkCode: %@",
          [self class], self, self.name, self.keychainItemRef, self.checkCode];
}

#pragma mark -
#pragma mark URL Validation


@end

@implementation TOTPAuthURL
static NSString *const TOTPAuthURLTimerNotification
  = @"TOTPAuthURLTimerNotification";

@synthesize generationAdvanceWarning = generationAdvanceWarning_;
@synthesize lastProgress = lastProgress_;
@synthesize warningSent = warningSent_;

+ (void)initialize {
  static NSTimer *sTOTPTimer = nil;
  if (!sTOTPTimer) {
    NSAutoreleasePool *pool = [[NSAutoreleasePool alloc] init];
    sTOTPTimer = [NSTimer scheduledTimerWithTimeInterval:1
                                                  target:self
                                                selector:@selector(totpTimer:)
                                                userInfo:nil
                                                 repeats:YES];
    [pool drain];
  }
}

+ (void)totpTimer:(NSTimer *)timer {
  NSNotificationCenter *nc = [NSNotificationCenter defaultCenter];
  [nc postNotificationName:TOTPAuthURLTimerNotification object:self];
}

- (id)initWithOTPGenerator:(OTPGenerator *)generator
                      name:(NSString *)name {
  if ((self = [super initWithOTPGenerator:generator
                                     name:name])) {
    [self setGenerationAdvanceWarning:kTOTPDefaultSecondsBeforeChange];
    [[NSNotificationCenter defaultCenter] addObserver:self
                                             selector:@selector(totpTimer:)
                                                 name:TOTPAuthURLTimerNotification
                                               object:nil];
  }
  return self;
}

- (id)initWithSecret:(NSData *)secret name:(NSString *)name {
  TOTPGenerator *generator
    = [[[TOTPGenerator alloc] initWithSecret:secret
                                   algorithm:[TOTPGenerator defaultAlgorithm]
                                      digits:[TOTPGenerator defaultDigits]
                                      period:[TOTPGenerator defaultPeriod]]
       autorelease];
  return [self initWithOTPGenerator:generator
                               name:name];
}

// totp:// urls are generated by the GAIA smsauthconfig page and implement
// a subset of the functionality available in otpauth:// urls, so we just
// translate to that internally.
- (id)initWithTOTPURL:(NSURL *)url {
  NSMutableString *name = nil;
  if ([[url user] length]) {
    name = [NSMutableString stringWithString:[url user]];
  }
  if ([url host]) {
    [name appendFormat:@"@%@", [url host]];
  }

  NSData *secret = [OTPAuthURL base32Decode:[url fragment]];
  return [self initWithSecret:secret name:name];
}

- (id)initWithName:(NSString *)name
            secret:(NSData *)secret
         algorithm:(NSString *)algorithm
            digits:(NSUInteger)digits
             query:(NSDictionary *)query {
  NSString *periodString = [query objectForKey:kQueryPeriodKey];
  NSTimeInterval period = 0;
  if (periodString) {
    period = [periodString doubleValue];
  } else {
    period = [TOTPGenerator defaultPeriod];
  }

  TOTPGenerator *generator
    = [[[TOTPGenerator alloc] initWithSecret:secret
                                   algorithm:algorithm
                                      digits:digits
                                      period:period] autorelease];

  if ((self = [self initWithOTPGenerator:generator
                                    name:name])) {
    self.lastProgress = period;
  }
  return self;
}

- (void)dealloc {
  [[NSNotificationCenter defaultCenter] removeObserver:self];
  [super dealloc];
}

- (NSString *)otpCode {
  return [self.generator generateOTP];
}

- (void)totpTimer:(NSTimer *)timer {
  TOTPGenerator *generator = (TOTPGenerator *)[self generator];
  NSTimeInterval delta = [[NSDate date] timeIntervalSince1970];
  NSTimeInterval period = [generator period];
  uint64_t progress = (uint64_t)delta % (uint64_t)period;
  NSNotificationCenter *nc = [NSNotificationCenter defaultCenter];
  if (progress == 0 || progress > self.lastProgress) {
    [nc postNotificationName:OTPAuthURLDidGenerateNewOTPNotification object:self];
    self.lastProgress = period;
    self.warningSent = NO;
  } else if (progress > period - self.generationAdvanceWarning
             && !self.warningSent) {
    NSNumber *warning = [NSNumber numberWithInt:ceil(period - progress)];
    NSDictionary *userInfo
      = [NSDictionary dictionaryWithObject:warning
                                    forKey:OTPAuthURLSecondsBeforeNewOTPKey];

    [nc postNotificationName:OTPAuthURLWillGenerateNewOTPWarningNotification
                      object:self
                    userInfo:userInfo];
    self.warningSent = YES;
  }
}

- (NSURL *)url {

  NSMutableDictionary *query = [NSMutableDictionary dictionary];
  TOTPGenerator *generator = (TOTPGenerator *)[self generator];
  Class generatorClass = [generator class];

  NSString *algorithm = [generator algorithm];
  if (![algorithm isEqualToString:[generatorClass defaultAlgorithm]]) {
    [query setObject:algorithm forKey:kQueryAlgorithmKey];
  }

  NSUInteger digits = [generator digits];
  if (digits != [generatorClass defaultDigits]) {
    id val = [NSNumber numberWithUnsignedInteger:digits];
    [query setObject:val forKey:kQueryDigitsKey];
  }

  NSTimeInterval period = [generator period];
  if (fpclassify(period - [generatorClass defaultPeriod]) != FP_ZERO) {
    id val = [NSNumber numberWithUnsignedInteger:period];
    [query setObject:val forKey:kQueryPeriodKey];
  }

  return [NSURL URLWithString:[NSString stringWithFormat:@"%@://totp/%@?%@",
                               kOTPAuthScheme,
                               [self.name gtm_stringByEscapingForURLArgument],
                               [query gtm_httpArgumentsString]]];
}

@end

@implementation HOTPAuthURL

@synthesize otpCode = otpCode_;

- (id)initWithOTPGenerator:(OTPGenerator *)generator
               name:(NSString *)name {
  if ((self = [super initWithOTPGenerator:generator name:name])) {
    uint64_t counter = [(HOTPGenerator *)generator counter];
    self.otpCode = [generator generateOTPForCounter:counter];
  }
  return self;
}


- (id)initWithSecret:(NSData *)secret name:(NSString *)name {
  HOTPGenerator *generator
    = [[[HOTPGenerator alloc] initWithSecret:secret
                                   algorithm:[HOTPGenerator defaultAlgorithm]
                                      digits:[HOTPGenerator defaultDigits]
                                     counter:[HOTPGenerator defaultInitialCounter]]
        autorelease];
  return [self initWithOTPGenerator:generator name:name];
}

- (id)initWithName:(NSString *)name
            secret:(NSData *)secret
         algorithm:(NSString *)algorithm
            digits:(NSUInteger)digits
             query:(NSDictionary *)query {
  NSString *counterString = [query objectForKey:kQueryCounterKey];
  if ([[self class] isValidCounter:counterString]) {
    NSScanner *scanner = [NSScanner scannerWithString:counterString];
    uint64_t counter;
    BOOL goodScan = [scanner gtm_scanUnsignedLongLong:&counter];
    // Good scan should always be good based on the isValidCounter check above.
    _GTMDevAssert(goodScan, @"goodscan should be true: %c", goodScan);
    HOTPGenerator *generator
      = [[[HOTPGenerator alloc] initWithSecret:secret
                                     algorithm:algorithm
                                        digits:digits
                                       counter:counter] autorelease];
    self = [self initWithOTPGenerator:generator
                                 name:name];
  } else {
    _GTMDevLog(@"invalid counter: %@", counterString);
    self = [super initWithOTPGenerator:nil name:nil];
    [self release];
    self = nil;
  }

  return self;
}

- (void)dealloc {
  self.otpCode = nil;
  [super dealloc];
}

- (void)generateNextOTPCode {
  self.otpCode = [[self generator] generateOTP];
  [self saveToKeychain];
  NSNotificationCenter *nc = [NSNotificationCenter defaultCenter];
  [nc postNotificationName:OTPAuthURLDidGenerateNewOTPNotification object:self];
}

- (NSURL *)url {
  NSMutableDictionary *query = [NSMutableDictionary dictionary];

  HOTPGenerator *generator = (HOTPGenerator *)[self generator];
  Class generatorClass = [generator class];

  NSString *algorithm = [generator algorithm];
  if (![algorithm isEqualToString:[generatorClass defaultAlgorithm]]) {
    [query setObject:algorithm forKey:kQueryAlgorithmKey];
  }

  NSUInteger digits = [generator digits];
  if (digits != [generatorClass defaultDigits]) {
    id val = [NSNumber numberWithUnsignedInteger:digits];
    [query setObject:val forKey:kQueryDigitsKey];
  }

  uint64_t counter = [generator counter];
  id val = [NSNumber numberWithUnsignedLongLong:counter];
  [query setObject:val forKey:kQueryCounterKey];

  return [NSURL URLWithString:[NSString stringWithFormat:@"%@://hotp/%@?%@",
                               kOTPAuthScheme,
                               [[self name] gtm_stringByEscapingForURLArgument],
                               [query gtm_httpArgumentsString]]];
}

+ (BOOL)isValidCounter:(NSString *)counter {
  NSCharacterSet *nonDigits =
    [[NSCharacterSet decimalDigitCharacterSet] invertedSet];
  NSRange pos = [counter rangeOfCharacterFromSet:nonDigits];
  return pos.location == NSNotFound;
}

@end

