//
//  UIColor+MobileColors.m
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

#import "UIColor+MobileColors.h"

@implementation UIColor (GMOMobileColors)
// Colors derived from the Cirrus UI spec:
// https://sites.google.com/a/google.com/guig/mobilewebapps/cirrus-visual-style
+ (UIColor *)googleBlueBarColor {
  return [UIColor colorWithRed:(float)0x5C/0xFF
                         green:(float)0x7D/0xFF
                          blue:(float)0xD2/0xFF
                         alpha:1.0];
}

+ (UIColor *)googleBlueBackgroundColor {
  return [UIColor colorWithRed:(float)0xEB/0xFF
                         green:(float)0xEF/0xFF
                          blue:(float)0xF9/0xFF
                         alpha:1.0];
}

+ (UIColor *)googleReadItemBackgroundColor {
  return [UIColor colorWithRed:(float)0xF3/0xFF
                         green:(float)0xF5/0xFF
                          blue:(float)0xFC/0xFF
                         alpha:1.0];
}

+ (UIColor *)googleTableViewSeparatorColor {
  return [UIColor colorWithWhite:0.95
                         alpha:1.0];
}

+ (UIColor *)googleBlueTextColor {
  return [UIColor colorWithRed:(float)0x33/0xFF
                         green:(float)0x55/0xFF
                          blue:(float)0x99/0xFF
                         alpha:1.0];
}

+ (UIColor *)googleGreenURLTextColor {
  return [UIColor colorWithRed:(float)0x7F/0xFF
                         green:(float)0xA8/0xFF
                          blue:(float)0x7F/0xFF
                         alpha:1.0];
}

+ (UIColor *)googleAdYellowBackgroundColor {
  return [UIColor colorWithRed:1.0     // 255
                         green:0.9725  // 248
                          blue:0.8667  // 221
                         alpha:1.0];
}

@end

CGGradientRef GoogleCreateBlueBarGradient(void) {
  CGGradientRef gradient = NULL;
  CGColorSpaceRef deviceRGB = CGColorSpaceCreateDeviceRGB();
  if (!deviceRGB) goto noDeviceRGB;
  CGFloat color1Comp[] = { (CGFloat)0x98 / (CGFloat)0xFF,
                           (CGFloat)0xAC / (CGFloat)0xFF,
                           (CGFloat)0xE2 / (CGFloat)0xFF,
                           1.0};
  CGFloat color2Comp[] = { (CGFloat)0x67 / (CGFloat)0xFF,
                           (CGFloat)0x86 / (CGFloat)0xFF,
                           (CGFloat)0xD5 / (CGFloat)0xFF,
                           1.0 };
  CGFloat color3Comp[] = { (CGFloat)0x5C / (CGFloat)0xFF,
                           (CGFloat)0x7D / (CGFloat)0xFF,
                           (CGFloat)0xD2 / (CGFloat)0xFF,
                           1.0 };
  CGFloat color4Comp[] = { (CGFloat)0x4A / (CGFloat)0xFF,
                           (CGFloat)0x6A / (CGFloat)0xFF,
                           (CGFloat)0xCB / (CGFloat)0xFF,
                           1.0 };
  CGColorRef color1 = CGColorCreate(deviceRGB, color1Comp);
  if (!color1) goto noColor1;
  CGColorRef color2 = CGColorCreate(deviceRGB, color2Comp);
  if (!color2) goto noColor2;
  CGColorRef color3 = CGColorCreate(deviceRGB, color3Comp);
  if (!color3) goto noColor3;
  CGColorRef color4 = CGColorCreate(deviceRGB, color4Comp);
  if (!color4) goto noColor4;
  CGColorRef colors[] = { color1, color2, color3, color4 };
  CGFloat locations[] = {0, 0.5, 0.5, 1.0};
  CFArrayRef array = CFArrayCreate(NULL,
                                   (const void **)colors,
                                   sizeof(colors) / sizeof(colors[0]),
                                   &kCFTypeArrayCallBacks);
  if (!array) goto noArray;
  gradient = CGGradientCreateWithColors(deviceRGB, array, locations);

  CFRelease(array);
noArray:
  CFRelease(color4);
noColor4:
  CFRelease(color3);
noColor3:
  CFRelease(color2);
noColor2:
  CFRelease(color1);
noColor1:
  CFRelease(deviceRGB);
noDeviceRGB:
  return gradient;
}
