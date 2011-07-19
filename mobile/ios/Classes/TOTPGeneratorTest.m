//
//  TOTPGeneratorTest.m
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

#import "TOTPGenerator.h"

#import <SenTestingKit/SenTestingKit.h>

@interface TOTPGeneratorTest : SenTestCase
- (void)testTOTP;
@end

@implementation TOTPGeneratorTest

// http://www.ietf.org/rfc/rfc4226.txt
// Appendix B.  Test Vectors
// Only SHA1 defined in test vectors.

- (void)testTOTP {

  NSString *secret = @"12345678901234567890";
  NSData *secretData = [secret dataUsingEncoding:NSASCIIStringEncoding];

  NSTimeInterval intervals[] = { 1111111111, 1234567890, 2000000000 };

  NSArray *algorithms = [NSArray arrayWithObjects:
                         kOTPGeneratorSHA1Algorithm,
                         kOTPGeneratorSHA256Algorithm,
                         kOTPGeneratorSHA512Algorithm,
                         kOTPGeneratorSHAMD5Algorithm,
                         nil];
  NSArray *results = [NSArray arrayWithObjects:
                      // SHA1      SHA256     SHA512     MD5
                      @"050471", @"584430", @"380122", @"275841", // date1
                      @"005924", @"829826", @"671578", @"280616", // date2
                      @"279037", @"428693", @"464532", @"090484", // date3
                      nil];

  for (size_t i = 0, j = 0; i < sizeof(intervals)/sizeof(*intervals); i++) {
    for (NSString *algorithm in algorithms) {
      TOTPGenerator *generator
        = [[[TOTPGenerator alloc] initWithSecret:secretData
                                       algorithm:algorithm
                                          digits:6
                                          period:30] autorelease];

      NSDate *date = [NSDate dateWithTimeIntervalSince1970:intervals[i]];

      STAssertEqualObjects([results objectAtIndex:j],
                           [generator generateOTPForDate:date],
                           @"Invalid result %d, %@, %@", i, algorithm, date);
      j = j + 1;
    }
  }
}

@end
