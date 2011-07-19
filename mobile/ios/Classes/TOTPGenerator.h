//
//  TOTPGenerator.h
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

#import <Foundation/Foundation.h>
#import "OTPGenerator.h"

// The TOTPGenerator class generates a one-time password (OTP) using
// the Time-based One-time Password Algorithm described in:
// http://tools.ietf.org/html/draft-mraihi-totp-timebased
//
// Basically, we define TOTP as TOTP = HOTP(K, T) where T is an integer
// and represents the number of time steps between the initial counter
// time T0 and the current Unix time (i.e. the number of seconds elapsed
// since midnight UTC of January 1, 1970).
//
// More specifically T = (Current Unix time - T0) / X where:
//
// - X represents the time step in seconds (default value X = 30
//   seconds) and is a system parameter;
//
// - T0 is the Unix time to start counting time steps (default value is
//   0, Unix epoch) and is also a system parameter.
//
@interface TOTPGenerator : OTPGenerator

// The period to use when calculating the counter.
@property(assign, nonatomic, readonly) NSTimeInterval period;

+ (NSTimeInterval)defaultPeriod;

// Designated initializer.
- (id)initWithSecret:(NSData *)secret
           algorithm:(NSString *)algorithm
              digits:(NSUInteger)digits
              period:(NSTimeInterval)period;

// Instance method to generate an OTP using the |algorithm|, |secret|,
// |digits|, |period| and |now| values configured on the object.
// The return value is an NSString of |digits| length, with leading
// zero-padding as required.
- (NSString *)generateOTPForDate:(NSDate *)date;

@end
