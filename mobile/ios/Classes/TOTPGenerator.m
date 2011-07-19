//
//  TOTPGenerator.m
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
#import "GTMDefines.h"

@interface TOTPGenerator ()
@property(assign, nonatomic, readwrite) NSTimeInterval period;
@end

@implementation TOTPGenerator
@synthesize period = period_;

+ (NSTimeInterval)defaultPeriod {
  return 30;
}

- (id)initWithSecret:(NSData *)secret
           algorithm:(NSString *)algorithm
              digits:(NSUInteger)digits
              period:(NSTimeInterval)period {
  if ((self = [super initWithSecret:secret
                          algorithm:algorithm
                             digits:digits])) {

    if (period <= 0 || period > 300) {
      _GTMDevLog(@"Bad Period: %f", period);
      [self release];
      self = nil;
    } else {
      self.period = period;
    }
  }
  return self;
}

- (NSString *)generateOTP {
  return [self generateOTPForDate:[NSDate date]];
}

- (NSString *)generateOTPForDate:(NSDate *)date {
  if (!date) {
    // If no now date specified, use the current date.
    date = [NSDate date];
  }

  NSTimeInterval seconds = [date timeIntervalSince1970];
  uint64_t counter = (uint64_t)(seconds / self.period);
  return [super generateOTPForCounter:counter];
}

@end
