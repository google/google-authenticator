//
//  HOTPGeneratorTest.m
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

#import "HOTPGenerator.h"

#import <SenTestingKit/SenTestingKit.h>

@interface HOTPGeneratorTest : SenTestCase
- (void)testHOTP;
@end

@implementation HOTPGeneratorTest

// http://www.ietf.org/rfc/rfc4226.txt
// Appendix D - HOTP Algorithm: Test Values
- (void)testHOTP {
  NSString *secret = @"12345678901234567890";
  NSData *secretData = [secret dataUsingEncoding:NSASCIIStringEncoding];

  HOTPGenerator *generator
    = [[[HOTPGenerator alloc] initWithSecret:secretData
                                   algorithm:kOTPGeneratorSHA1Algorithm
                                      digits:6
                                     counter:0] autorelease];
  STAssertNotNil(generator, nil);

  STAssertEqualObjects(@"755224", [generator generateOTPForCounter:0], nil);

  // Make sure generating another OTP with generateOTPForCounter:
  // doesn't change our generator.
  STAssertEqualObjects(@"755224", [generator generateOTPForCounter:0], nil);

  NSArray *results = [NSArray arrayWithObjects:
                      @"287082", @"359152", @"969429", @"338314", @"254676",
                      @"287922", @"162583", @"399871", @"520489", @"403154",
                      nil];

  for (NSString *result in results) {
    STAssertEqualObjects(result, [generator generateOTP], @"Invalid result");
  }
}

@end
