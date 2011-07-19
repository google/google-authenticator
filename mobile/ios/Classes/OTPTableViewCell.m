//
//  OTPTableViewCell.m
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

#import "OTPTableViewCell.h"
#import "HOTPGenerator.h"
#import "OTPAuthURL.h"
#import "UIColor+MobileColors.h"
#import "GTMLocalizedString.h"
#import "GTMRoundedRectPath.h"
#import "GTMSystemVersion.h"

@interface OTPTableViewCell ()
@property (readwrite, retain, nonatomic) OTPAuthURL *authURL;
@property (readwrite, assign, nonatomic) BOOL showingInfo;
@property (readonly, nonatomic) BOOL shouldHideInfoButton;

- (void)updateUIForAuthURL:(OTPAuthURL *)authURL;
@end

@interface HOTPTableViewCell ()
- (void)otpAuthURLDidGenerateNewOTP:(NSNotification *)notification;
@end

@interface TOTPTableViewCell ()
- (void)otpAuthURLWillGenerateNewOTP:(NSNotification *)notification;
- (void)otpAuthURLDidGenerateNewOTP:(NSNotification *)notification;
@end

@implementation OTPTableViewCell

@synthesize frontCodeLabel = frontCodeLabel_;
@synthesize frontWarningLabel = frontWarningLabel_;
@synthesize backCheckLabel = backCheckLabel_;
@synthesize backIntegrityCheckLabel = backIntegrityCheckLabel_;
@synthesize frontNameTextField = frontNameTextField_;
@synthesize frontRefreshButton = frontRefreshButton_;
@synthesize frontInfoButton = frontInfoButton_;
@synthesize frontView = frontView_;
@synthesize backView = backView_;
@synthesize authURL = authURL_;
@synthesize showingInfo = showingInfo_;

- (id)initWithStyle:(UITableViewCellStyle)style
    reuseIdentifier:(NSString *)reuseIdentifier {
  if ((self = [super initWithStyle:style reuseIdentifier:reuseIdentifier])) {
    self.selectionStyle = UITableViewCellSelectionStyleNone;
  }
  return self;
}

- (void)dealloc {
  NSNotificationCenter *nc = [NSNotificationCenter defaultCenter];
  [nc removeObserver:self];
  self.frontCodeLabel = nil;
  self.frontWarningLabel = nil;
  self.backCheckLabel = nil;
  self.backIntegrityCheckLabel = nil;
  self.frontNameTextField = nil;
  self.frontRefreshButton = nil;
  self.frontInfoButton = nil;
  self.frontView = nil;
  self.backView = nil;
  self.authURL = nil;

  [super dealloc];
}

- (void)layoutSubviews {
  [super layoutSubviews];
  if (!self.frontView) {
    [[NSBundle mainBundle] loadNibNamed:@"OTPTableViewCell"
                                  owner:self
                                options:nil];
    CGRect bounds = self.contentView.bounds;
    self.frontView.frame = bounds;
    [self.contentView addSubview:self.frontView];
    [self updateUIForAuthURL:self.authURL];
    self.backIntegrityCheckLabel.text =
        GTMLocalizedString(@"Integrity Check Value",
                           @"Integerity Check Value label");
  }
}

- (void)updateUIForAuthURL:(OTPAuthURL *)authURL {
  self.frontNameTextField.text = authURL.name;
  NSString *otpCode = authURL.otpCode;
  self.frontCodeLabel.text = otpCode;
  self.frontWarningLabel.text = otpCode;
  self.backCheckLabel.text = authURL.checkCode;
  self.frontInfoButton.hidden = self.shouldHideInfoButton;
}

- (void)setAuthURL:(OTPAuthURL *)authURL {
  NSNotificationCenter *nc = [NSNotificationCenter defaultCenter];
  [nc removeObserver:self
                name:OTPAuthURLDidGenerateNewOTPNotification
              object:authURL_];
  [authURL_ autorelease];
  authURL_ = [authURL retain];
  [self updateUIForAuthURL:authURL_];
  [nc addObserver:self
         selector:@selector(otpAuthURLDidGenerateNewOTP:)
             name:OTPAuthURLDidGenerateNewOTPNotification
           object:authURL_];
}

- (void)willBeginEditing {
  [self.frontNameTextField becomeFirstResponder];
}

- (void)didEndEditing {
  [self.frontNameTextField resignFirstResponder];
}

- (void)otpChangeDidStop:(NSString *)animationID
                finished:(NSNumber *)finished
                 context:(void *)context {
  // We retain ourself whenever we start an animation that calls
  // setAnimationStopSelector, so we must release ourself when we are actually
  // called. This is so that we don't disappear out from underneath the
  // animation while it is running.
  if ([animationID isEqual:@"otpFadeOut"]) {
    self.frontWarningLabel.alpha = 0;
    self.frontCodeLabel.alpha = 0;
    NSString *otpCode = self.authURL.otpCode;
    self.frontCodeLabel.text = otpCode;
    self.frontWarningLabel.text = otpCode;
    [UIView beginAnimations:@"otpFadeIn" context:nil];
    [UIView setAnimationDelegate:self];
    [self retain];
    [UIView setAnimationDidStopSelector:@selector(otpChangeDidStop:finished:context:)];
    self.frontCodeLabel.alpha = 1;
    [UIView commitAnimations];
  } else {
    self.frontCodeLabel.alpha = 1;
    self.frontWarningLabel.alpha = 0;
    self.frontWarningLabel.hidden = YES;
  }
  [self release];
}

- (BOOL)canBecomeFirstResponder {
  return YES;
}

- (void)showCopyMenu:(CGPoint)location {
  if (self.showingInfo) return;
  UIView *view = self.frontCodeLabel;
  CGRect selectionRect = [view frame];
  if (CGRectContainsPoint(selectionRect, location) &&
      [self becomeFirstResponder]) {
    UIMenuController *theMenu = [UIMenuController sharedMenuController];
    [theMenu setTargetRect:selectionRect inView:[view superview]];
    [theMenu setMenuVisible:YES animated:YES];
  }
}

- (BOOL)canPerformAction:(SEL)action withSender:(id)sender {
  BOOL canPerform = NO;
  if (action == @selector(copy:)) {
    canPerform = YES;
  } else {
    canPerform = [super canPerformAction:action withSender:sender];
  }
  return canPerform;
}

- (BOOL)textFieldShouldReturn:(UITextField *)textField {
  [textField resignFirstResponder];
  return YES;
}

- (void)setEditing:(BOOL)editing animated:(BOOL)animated {
  [super setEditing:editing animated:animated];
  if (!editing) {
    if (![self.authURL.name isEqual:self.frontNameTextField.text]) {
      self.authURL.name = self.frontNameTextField.text;
      // Write out the changes.
      [self.authURL saveToKeychain];
    }
    [self.frontNameTextField resignFirstResponder];
    self.frontNameTextField.userInteractionEnabled = NO;
    self.frontNameTextField.borderStyle = UITextBorderStyleNone;
    if (!self.shouldHideInfoButton) {
      self.frontInfoButton.hidden = NO;
    }
  } else {
    self.frontNameTextField.userInteractionEnabled = YES;
    self.frontNameTextField.borderStyle = UITextBorderStyleRoundedRect;
    self.frontInfoButton.hidden = YES;
    [self hideInfo:self];
  }
}

- (BOOL)shouldHideInfoButton {
  return [self.authURL isKindOfClass:[TOTPAuthURL class]];
}

#pragma mark -
#pragma mark Actions

- (IBAction)copy:(id)sender {
  UIPasteboard *pb = [UIPasteboard generalPasteboard];
  [pb setValue:self.frontCodeLabel.text forPasteboardType:@"public.utf8-plain-text"];
}

- (IBAction)showInfo:(id)sender {
  if (!self.showingInfo) {
    self.backView.frame = self.contentView.bounds;
    [UIView beginAnimations:@"showInfo" context:NULL];
    [UIView setAnimationTransition:UIViewAnimationTransitionFlipFromRight
                           forView:self.contentView
                             cache:YES];
    [self.frontView removeFromSuperview];
    [self.contentView addSubview:self.backView];
    [UIView commitAnimations];
    self.showingInfo = YES;
  }
}

- (IBAction)hideInfo:(id)sender {
  if (self.showingInfo) {
    self.frontView.frame = self.contentView.bounds;
    [UIView beginAnimations:@"hideInfo" context:NULL];
    [UIView setAnimationTransition:UIViewAnimationTransitionFlipFromLeft
                           forView:self.contentView
                             cache:YES];
    [backView_ removeFromSuperview];
    [self.contentView addSubview:self.frontView];
    [UIView commitAnimations];
    self.showingInfo = NO;
  }
}

- (IBAction)refreshAuthURL:(id)sender {
  // For subclasses to override.
}

@end

#pragma mark -

@implementation HOTPTableViewCell

- (void)layoutSubviews {
  [super layoutSubviews];
  self.frontRefreshButton.hidden = self.isEditing;
}

- (void)setEditing:(BOOL)editing animated:(BOOL)animated {
  [super setEditing:editing animated:animated];
  if (!editing) {
    self.frontRefreshButton.hidden = NO;
  } else {
    self.frontRefreshButton.hidden = YES;
  }
}

- (IBAction)refreshAuthURL:(id)sender {
  [(HOTPAuthURL *)self.authURL generateNextOTPCode];
}

- (void)otpAuthURLDidGenerateNewOTP:(NSNotification *)notification {
  self.frontCodeLabel.alpha = 1;
  self.frontWarningLabel.alpha = 0;
  [UIView beginAnimations:@"otpFadeOut" context:nil];
  [UIView setAnimationDelegate:self];
  [self retain];
  [UIView setAnimationDidStopSelector:@selector(otpChangeDidStop:finished:context:)];
  self.frontCodeLabel.alpha = 0;
  [UIView commitAnimations];
}

@end

#pragma mark -

@implementation TOTPTableViewCell

- (id)initWithStyle:(UITableViewCellStyle)style
    reuseIdentifier:(NSString *)reuseIdentifier {
  if ((self = [super initWithStyle:style reuseIdentifier:reuseIdentifier])) {
    // Only support backgrounding in iOS 4+.
    if (&UIApplicationWillEnterForegroundNotification != NULL) {
      NSNotificationCenter *nc = [NSNotificationCenter defaultCenter];
      [nc addObserver:self
             selector:@selector(applicationWillEnterForeground:)
                 name:UIApplicationWillEnterForegroundNotification
               object:nil];
    }
  }
  return self;
}

- (void)dealloc {
  NSNotificationCenter *nc = [NSNotificationCenter defaultCenter];
  [nc removeObserver:self];
  [super dealloc];
}

// On iOS4+ we need to make sure our timer based codes are up to date
// if we have been hidden in the background.
- (void)applicationWillEnterForeground:(UIApplication *)application {
  NSString *code = self.authURL.otpCode;
  NSString *frontText = self.frontCodeLabel.text;
  if (![code isEqual:frontText]) {
    [self otpAuthURLDidGenerateNewOTP:nil];
  }
}

- (void)setAuthURL:(OTPAuthURL *)authURL {
  NSNotificationCenter *nc = [NSNotificationCenter defaultCenter];
  [nc removeObserver:self
                name:OTPAuthURLWillGenerateNewOTPWarningNotification
              object:self.authURL];
  super.authURL = authURL;
  [nc addObserver:self
         selector:@selector(otpAuthURLWillGenerateNewOTP:)
             name:OTPAuthURLWillGenerateNewOTPWarningNotification
           object:self.authURL];
}

- (void)otpAuthURLWillGenerateNewOTP:(NSNotification *)notification {
  NSDictionary *userInfo = [notification userInfo];
  NSNumber *nsSeconds
    = [userInfo objectForKey:OTPAuthURLSecondsBeforeNewOTPKey];
  NSUInteger seconds = [nsSeconds unsignedIntegerValue];
  self.frontWarningLabel.alpha = 0;
  self.frontWarningLabel.hidden = NO;
  [UIView beginAnimations:@"Warning" context:nil];
  [UIView setAnimationDuration:seconds];
  self.frontCodeLabel.alpha = 0;
  self.frontWarningLabel.alpha = 1;
  [UIView commitAnimations];
}

- (void)otpAuthURLDidGenerateNewOTP:(NSNotification *)notification {
  self.frontCodeLabel.alpha = 0;
  self.frontWarningLabel.alpha = 1;
  [UIView beginAnimations:@"otpFadeOut" context:nil];
  [UIView setAnimationDelegate:self];
  [self retain];
  [UIView setAnimationDidStopSelector:@selector(otpChangeDidStop:finished:context:)];
  self.frontWarningLabel.alpha = 0;
  [UIView commitAnimations];
}

@end

#pragma mark -

@implementation OTPTableViewCellBackView

- (id)initWithFrame:(CGRect)frame {
  if ((self = [super initWithFrame:frame])) {
    self.opaque = NO;
    self.clearsContextBeforeDrawing = YES;
  }
  return self;
}

- (void)drawRect:(CGRect)rect {
  CGGradientRef gradient = GoogleCreateBlueBarGradient();
  if (gradient) {
    CGContextRef context = UIGraphicsGetCurrentContext();
    GTMCGContextAddRoundRect(context, self.bounds, 8);
    CGContextClip(context);
    CGPoint midTop = CGPointMake(CGRectGetMidX(rect), CGRectGetMinY(rect));
    CGPoint midBottom = CGPointMake(CGRectGetMidX(rect), CGRectGetMaxY(rect));
    CGContextDrawLinearGradient(context, gradient, midTop, midBottom, 0);
    CFRelease(gradient);
  }
}

@end
