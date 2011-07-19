//
//  OTPScannerOverlayView.m
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

#import "OTPScannerOverlayView.h"

@implementation OTPScannerOverlayView

- (id)initWithFrame:(CGRect)frame {
  if ((self = [super initWithFrame:frame])) {
    self.opaque = NO;
    self.autoresizingMask
      = UIViewAutoresizingFlexibleWidth | UIViewAutoresizingFlexibleHeight;
  }
  return self;
}

- (void)drawRect:(CGRect)rect {
  CGContextRef context = UIGraphicsGetCurrentContext();
  CGRect bounds = self.bounds;
  CGFloat rectHeight = 200;
  CGFloat oneSixthRectHeight = rectHeight * 0.165;
  CGFloat midX = CGRectGetMidX(bounds);
  CGFloat midY = CGRectGetMidY(bounds);
  CGFloat minY = CGRectGetMinY(bounds);
  CGFloat minX = CGRectGetMinX(bounds);
  CGFloat maxY = CGRectGetMaxY(bounds);
  CGFloat maxX = CGRectGetMaxX(bounds);

  // Blackout boxes
  CGRect scanRect = CGRectMake(midX - rectHeight * .5,
                               midY - rectHeight * .5,
                               rectHeight,
                               rectHeight);
  CGRect leftRect = CGRectMake(minX, minY,
                               CGRectGetMinX(scanRect), maxY);
  CGRect rightRect = CGRectMake(CGRectGetMaxX(scanRect), minY,
                                maxX - CGRectGetMaxX(scanRect), maxY);
  CGRect bottomRect = CGRectMake(minX, minY,
                                 maxX, CGRectGetMinY(scanRect));
  CGRect topRect = CGRectMake(CGRectGetMinX(scanRect), CGRectGetMaxY(scanRect),
                              maxX, maxY - CGRectGetMaxY(scanRect));
  CGContextBeginPath(context);
  CGContextAddRect(context, leftRect);
  CGContextAddRect(context, rightRect);
  CGContextAddRect(context, bottomRect);
  CGContextAddRect(context, topRect);
  [[[UIColor blackColor] colorWithAlphaComponent:0.3] set];
  CGContextFillPath(context);

  // Frame Box
  [[UIColor greenColor] set];
  midX = CGRectGetMidX(scanRect);
  midY = CGRectGetMidY(scanRect);
  minY = CGRectGetMinY(scanRect);
  minX = CGRectGetMinX(scanRect);
  maxY = CGRectGetMaxY(scanRect);
  maxX = CGRectGetMaxX(scanRect);
  CGContextSetLineWidth(context, 2);
  CGContextMoveToPoint(context, midX - oneSixthRectHeight, minY);
  CGContextAddLineToPoint(context, minX, minY);
  CGContextAddLineToPoint(context, minX, midY - oneSixthRectHeight);
  CGContextStrokePath(context);
  CGContextMoveToPoint(context, minX, midY + oneSixthRectHeight);
  CGContextAddLineToPoint(context, minX, maxY);
  CGContextAddLineToPoint(context, midX - oneSixthRectHeight, maxY);
  CGContextStrokePath(context);
  CGContextMoveToPoint(context, midX + oneSixthRectHeight, maxY);
  CGContextAddLineToPoint(context, maxX, maxY);
  CGContextAddLineToPoint(context, maxX, midY + oneSixthRectHeight);
  CGContextStrokePath(context);
  CGContextMoveToPoint(context, maxX, midY - oneSixthRectHeight);
  CGContextAddLineToPoint(context, maxX, minY);
  CGContextAddLineToPoint(context, midX + oneSixthRectHeight, minY);
  CGContextStrokePath(context);

  // Cross hairs
  CGContextSetLineWidth(context, 1);
  CGContextMoveToPoint(context, midX, minY - oneSixthRectHeight);
  CGContextAddLineToPoint(context, midX, minY + oneSixthRectHeight);
  CGContextStrokePath(context);
  CGContextMoveToPoint(context, midX, maxY - oneSixthRectHeight);
  CGContextAddLineToPoint(context, midX, maxY + oneSixthRectHeight);
  CGContextStrokePath(context);
  CGContextMoveToPoint(context, minX - oneSixthRectHeight, midY);
  CGContextAddLineToPoint(context, minX + oneSixthRectHeight, midY);
  CGContextStrokePath(context);
  CGContextMoveToPoint(context, maxX - oneSixthRectHeight, midY);
  CGContextAddLineToPoint(context, maxX + oneSixthRectHeight, midY);
  CGContextStrokePath(context);
}

@end
