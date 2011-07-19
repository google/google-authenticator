//
//  UIColor+MobileColors.h
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

// This header defines shared colors for all native iPhone Google
// apps.

#import <UIKit/UIKit.h>

@interface UIColor (GMOMobileColors)
+ (UIColor *)googleBlueBarColor;
+ (UIColor *)googleBlueBackgroundColor;
+ (UIColor *)googleTableViewSeparatorColor;
+ (UIColor *)googleReadItemBackgroundColor;
+ (UIColor *)googleBlueTextColor;
+ (UIColor *)googleGreenURLTextColor;
+ (UIColor *)googleAdYellowBackgroundColor;
@end

// Returns a gradient that mimics a navigation bar tinted with
// googleBlueBarColor. Client responsible for releasing.
CGGradientRef GoogleCreateBlueBarGradient();
