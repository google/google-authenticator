//
//  OTPAuthURLEntryController.m
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

#import "OTPAuthURLEntryController.h"
#import <MobileCoreServices/MobileCoreServices.h>
#import "OTPAuthURL.h"
#import "GTMNSString+URLArguments.h"
#import "HOTPGenerator.h"
#import "TOTPGenerator.h"
#import "Decoder.h"
#import "TwoDDecoderResult.h"
#import "OTPScannerOverlayView.h"
#import "GTMLocalizedString.h"
#import "UIColor+MobileColors.h"

@interface OTPAuthURLEntryController ()
@property(nonatomic, readwrite, assign) UITextField *activeTextField;
@property(nonatomic, readwrite, assign) UIBarButtonItem *doneButtonItem;
@property(nonatomic, readwrite, retain) Decoder *decoder;
// queue is retained using dispatch_queue retain semantics.
@property (nonatomic, retain) __attribute__((NSObject)) dispatch_queue_t queue;
@property (nonatomic, retain) AVCaptureSession *avSession;
@property BOOL handleCapture;

- (void)keyboardWasShown:(NSNotification*)aNotification;
- (void)keyboardWillBeHidden:(NSNotification*)aNotification;
@end

@implementation OTPAuthURLEntryController
@synthesize delegate = delegate_;
@synthesize doneButtonItem = doneButtonItem_;
@synthesize accountName = accountName_;
@synthesize accountKey = accountKey_;
@synthesize accountNameLabel = accountNameLabel_;
@synthesize accountKeyLabel = accountKeyLabel_;
@synthesize accountType = accountType_;
@synthesize scanBarcodeButton = scanBarcodeButton_;
@synthesize scrollView = scrollView_;
@synthesize activeTextField = activeTextField_;
@synthesize decoder = decoder_;
@dynamic queue;
@synthesize avSession = avSession_;
@synthesize handleCapture = handleCapture_;

- (BOOL)shouldAutorotateToInterfaceOrientation:(UIInterfaceOrientation)interfaceOrientation {
  if (UI_USER_INTERFACE_IDIOM() == UIUserInterfaceIdiomPad) {
    // On an iPad, support both portrait modes and landscape modes.
    return UIInterfaceOrientationIsLandscape(interfaceOrientation) ||
           UIInterfaceOrientationIsPortrait(interfaceOrientation);
  }
  // On a phone/pod, don't support upside-down portrait.
  return interfaceOrientation == UIInterfaceOrientationPortrait ||
         UIInterfaceOrientationIsLandscape(interfaceOrientation);
}

- (void)dealloc {
  NSNotificationCenter *nc = [NSNotificationCenter defaultCenter];
  [nc removeObserver:self];
  self.delegate = nil;
  self.doneButtonItem = nil;
  self.accountName = nil;
  self.accountKey = nil;
  self.accountNameLabel = nil;
  self.accountKeyLabel = nil;
  self.accountType = nil;
  self.scanBarcodeButton = nil;
  self.scrollView = nil;
  self.decoder = nil;
  self.queue = nil;
  self.avSession = nil;
  self.queue = nil;
  [super dealloc];
}

- (void)viewDidLoad {
  self.accountName.placeholder
    = GTMLocalizedString(@"user@example.com",
                         @"Placeholder string for used acccount");
  self.accountNameLabel.text
    = GTMLocalizedString(@"Account:",
                         @"Label for Account field");
  self.accountKey.placeholder
    = GTMLocalizedString(@"Enter your key",
                         @"Placeholder string for key field");
  self.accountKeyLabel.text
    = GTMLocalizedString(@"Key:",
                         @"Label for Key field");
  [self.scanBarcodeButton setTitle:GTMLocalizedString(@"Scan Barcode",
                                                      @"Scan Barcode button title")
                          forState:UIControlStateNormal];
  [self.accountType setTitle:GTMLocalizedString(@"Time Based",
                                                @"Time Based Account Type")
      forSegmentAtIndex:0];
  [self.accountType setTitle:GTMLocalizedString(@"Counter Based",
                                                @"Counter Based Account Type")
      forSegmentAtIndex:1];

  NSNotificationCenter *nc = [NSNotificationCenter defaultCenter];
  [nc addObserver:self
         selector:@selector(keyboardWasShown:)
             name:UIKeyboardDidShowNotification object:nil];

  [nc addObserver:self
         selector:@selector(keyboardWillBeHidden:)
             name:UIKeyboardWillHideNotification object:nil];
}

- (void)viewWillAppear:(BOOL)animated {
  self.accountName.text = @"";
  self.accountKey.text = @"";
  self.doneButtonItem
    = self.navigationController.navigationBar.topItem.rightBarButtonItem;
  self.doneButtonItem.enabled = NO;
  self.decoder = [[[Decoder alloc] init] autorelease];
  self.decoder.delegate = self;
  self.scrollView.backgroundColor = [UIColor googleBlueBackgroundColor];

  // Hide the Scan button if we don't have a camera that will support video.
  AVCaptureDevice *device = nil;
  if ([AVCaptureDevice class]) {
    // AVCaptureDevice is not supported on iOS 3.1.3
    device = [AVCaptureDevice defaultDeviceWithMediaType:AVMediaTypeVideo];
  }
  if (!device) {
    [self.scanBarcodeButton setHidden:YES];
  }
}

- (void)viewWillDisappear:(BOOL)animated {
  self.doneButtonItem = nil;
  self.handleCapture = NO;
  [self.avSession stopRunning];
}

- (dispatch_queue_t)queue {
  return queue_;
}

- (void)setQueue:(dispatch_queue_t)aQueue {
  if (queue_ != aQueue) {
    if (queue_) {
      dispatch_release(queue_);
    }
    queue_ = aQueue;
    if (queue_) {
      dispatch_retain(queue_);
    }
  }
}

// Called when the UIKeyboardDidShowNotification is sent.
- (void)keyboardWasShown:(NSNotification*)aNotification {
  NSDictionary* info = [aNotification userInfo];
  CGFloat offset = 0;

  // UIKeyboardFrameBeginUserInfoKey does not exist on iOS 3.1.3
  if (&UIKeyboardFrameBeginUserInfoKey != NULL) {
    NSValue *sizeValue = [info objectForKey:UIKeyboardFrameBeginUserInfoKey];
    CGSize keyboardSize = [sizeValue CGRectValue].size;
    BOOL isLandscape
      = UIInterfaceOrientationIsLandscape(self.interfaceOrientation);
    offset = isLandscape ? keyboardSize.width : keyboardSize.height;
  } else {
    NSValue *sizeValue = [info objectForKey:UIKeyboardBoundsUserInfoKey];
    CGSize keyboardSize = [sizeValue CGRectValue].size;
    // The keyboard size value appears to rotate correctly on iOS 3.1.3.
    offset = keyboardSize.height;
  }

  UIEdgeInsets contentInsets = UIEdgeInsetsMake(0.0, 0.0, offset, 0.0);
  self.scrollView.contentInset = contentInsets;
  self.scrollView.scrollIndicatorInsets = contentInsets;

  // If active text field is hidden by keyboard, scroll it so it's visible.
  CGRect aRect = self.view.frame;
  aRect.size.height -= offset;
  if (self.activeTextField) {
    CGPoint origin = self.activeTextField.frame.origin;
    origin.y += CGRectGetHeight(self.activeTextField.frame);
    if (!CGRectContainsPoint(aRect, origin) ) {
      CGPoint scrollPoint =
          CGPointMake(0.0, - (self.activeTextField.frame.origin.y - offset));
      [self.scrollView setContentOffset:scrollPoint animated:YES];
    }
  }
}

- (void)keyboardWillBeHidden:(NSNotification*)aNotification {
  UIEdgeInsets contentInsets = UIEdgeInsetsZero;
  self.scrollView.contentInset = contentInsets;
  self.scrollView.scrollIndicatorInsets = contentInsets;
}


- (void)didRotateFromInterfaceOrientation:(UIInterfaceOrientation)orientation {
  // Scrolling is only enabled when in landscape.
  if (UIInterfaceOrientationIsLandscape(self.interfaceOrientation)) {
    self.scrollView.contentSize = self.view.bounds.size;
  } else {
    self.scrollView.contentSize = CGSizeZero;
  }
}

#pragma mark -
#pragma mark Actions

- (IBAction)accountNameDidEndOnExit:(id)sender {
  [self.accountKey becomeFirstResponder];
}

- (IBAction)accountKeyDidEndOnExit:(id)sender {
  [self done:sender];
}

- (IBAction)done:(id)sender {
  // Force the keyboard away.
  [self.activeTextField resignFirstResponder];

  NSString *encodedSecret = self.accountKey.text;
  NSData *secret = [OTPAuthURL base32Decode:encodedSecret];

  if ([secret length]) {
    Class authURLClass = Nil;
    if ([accountType_ selectedSegmentIndex] == 0) {
      authURLClass = [TOTPAuthURL class];
    } else {
      authURLClass = [HOTPAuthURL class];
    }
    NSString *name = self.accountName.text;
    OTPAuthURL *authURL
      = [[[authURLClass alloc] initWithSecret:secret
                                         name:name] autorelease];
    NSString *checkCode = authURL.checkCode;
    if (checkCode) {
      [self.delegate authURLEntryController:self didCreateAuthURL:authURL];
    }
  } else {
    NSString *title = GTMLocalizedString(@"Invalid Key",
                                         @"Alert title describing a bad key");
    NSString *message = nil;
    if ([encodedSecret length]) {
      message = [NSString stringWithFormat:
                 GTMLocalizedString(@"The key '%@' is invalid.",
                                    @"Alert describing invalid key"),
                 encodedSecret];
    } else {
      message = GTMLocalizedString(@"You must enter a key.",
                                   @"Alert describing missing key");
    }
    NSString *button
      = GTMLocalizedString(@"Try Again",
                           @"Button title to try again");
    UIAlertView *alert = [[[UIAlertView alloc] initWithTitle:title
                                                     message:message
                                                    delegate:nil
                                           cancelButtonTitle:button
                                           otherButtonTitles:nil]
                          autorelease];
    [alert show];
  }
}

- (IBAction)cancel:(id)sender {
  self.handleCapture = NO;
  [self.avSession stopRunning];
  [self dismissModalViewControllerAnimated:NO];
}

- (IBAction)scanBarcode:(id)sender {
  if (!self.avSession) {
    self.avSession = [[[AVCaptureSession alloc] init] autorelease];
    AVCaptureDevice *device =
      [AVCaptureDevice defaultDeviceWithMediaType:AVMediaTypeVideo];
    AVCaptureDeviceInput *captureInput =
      [AVCaptureDeviceInput deviceInputWithDevice:device error:nil];
    [self.avSession addInput:captureInput];
    dispatch_queue_t queue = dispatch_queue_create("OTPAuthURLEntryController",
                                                   0);
    self.queue = queue;
    dispatch_release(queue);
    AVCaptureVideoDataOutput *captureOutput =
      [[[AVCaptureVideoDataOutput alloc] init] autorelease];
    [captureOutput setAlwaysDiscardsLateVideoFrames:YES];
    [captureOutput setMinFrameDuration:CMTimeMake(5,1)];  // At most 5 frames/sec.
    [captureOutput setSampleBufferDelegate:self
                                     queue:self.queue];
    NSNumber *bgra = [NSNumber numberWithUnsignedInt:kCVPixelFormatType_32BGRA];
    NSDictionary *videoSettings = [NSDictionary dictionaryWithObjectsAndKeys:
                                   bgra, kCVPixelBufferPixelFormatTypeKey,
                                   nil];
    [captureOutput setVideoSettings:videoSettings];
    [self.avSession addOutput:captureOutput];
  }

  AVCaptureVideoPreviewLayer *previewLayer
    = [AVCaptureVideoPreviewLayer layerWithSession:self.avSession];
  [previewLayer setVideoGravity:AVLayerVideoGravityResizeAspectFill];

  UIButton *cancelButton =
    [UIButton buttonWithType:UIButtonTypeRoundedRect];
  NSString *cancelString
    = GTMLocalizedString(@"Cancel", @"Cancel button for taking pictures");
  cancelButton.accessibilityLabel = @"Cancel";
  CGFloat height = [UIFont systemFontSize];
  CGSize size
    = [cancelString sizeWithFont:[UIFont systemFontOfSize:height]];
  [cancelButton setTitle:cancelString forState:UIControlStateNormal];

  UIViewController *previewController
    = [[[UIViewController alloc] init] autorelease];
  [previewController.view.layer addSublayer:previewLayer];

  CGRect frame = previewController.view.bounds;
  previewLayer.frame = frame;
  OTPScannerOverlayView *overlayView
    = [[[OTPScannerOverlayView alloc] initWithFrame:frame] autorelease];
  [previewController.view addSubview:overlayView];

  // Center the cancel button horizontally, and put it
  // kBottomPadding from the bottom of the view.
  static const int kBottomPadding = 10;
  static const int kInternalXMargin = 10;
  static const int kInternalYMargin = 10;
  frame = CGRectMake(CGRectGetMidX(frame)
                            - ((size.width / 2) + kInternalXMargin),
                            CGRectGetHeight(frame)
                            - (height + (2 * kInternalYMargin) + kBottomPadding),
                            (2  * kInternalXMargin) + size.width,
                            height + (2 * kInternalYMargin));
  [cancelButton setFrame:frame];

  // Set it up so that if the view should resize, the cancel button stays
  // h-centered and v-bottom-fixed in the view.
  cancelButton.autoresizingMask = (UIViewAutoresizingFlexibleTopMargin |
                                   UIViewAutoresizingFlexibleLeftMargin |
                                   UIViewAutoresizingFlexibleRightMargin);
  [cancelButton addTarget:self
                   action:@selector(cancel:)
         forControlEvents:UIControlEventTouchUpInside];
  [overlayView addSubview:cancelButton];

  [self presentModalViewController:previewController animated:NO];
  self.handleCapture = YES;
  [self.avSession startRunning];
}

- (void)captureOutput:(AVCaptureOutput *)captureOutput
didOutputSampleBuffer:(CMSampleBufferRef)sampleBuffer
       fromConnection:(AVCaptureConnection *)connection {
  if (!self.handleCapture) return;
  NSAutoreleasePool *pool = [[NSAutoreleasePool alloc] init];
  CVImageBufferRef imageBuffer = CMSampleBufferGetImageBuffer(sampleBuffer);
  if (imageBuffer) {
    CVReturn ret = CVPixelBufferLockBaseAddress(imageBuffer, 0);
    if (ret == kCVReturnSuccess) {
      uint8_t *base = (uint8_t *)CVPixelBufferGetBaseAddress(imageBuffer);
      size_t bytesPerRow = CVPixelBufferGetBytesPerRow(imageBuffer);
      size_t width = CVPixelBufferGetWidth(imageBuffer);
      size_t height = CVPixelBufferGetHeight(imageBuffer);
      CGColorSpaceRef colorSpace = CGColorSpaceCreateDeviceRGB();
      CGContextRef context
        = CGBitmapContextCreate(base, width, height, 8, bytesPerRow, colorSpace,
                                kCGBitmapByteOrder32Little | kCGImageAlphaPremultipliedFirst);
      CGColorSpaceRelease(colorSpace);
      CGImageRef cgImage = CGBitmapContextCreateImage(context);
      CGContextRelease(context);
      UIImage *image = [UIImage imageWithCGImage:cgImage];
      CFRelease(cgImage);
      CVPixelBufferUnlockBaseAddress(imageBuffer, 0);
      [self.decoder performSelectorOnMainThread:@selector(decodeImage:)
                                     withObject:image
                                  waitUntilDone:NO];
    } else {
      NSLog(@"Unable to lock buffer %d", ret);
    }
  } else {
    NSLog(@"Unable to get imageBuffer from %@", sampleBuffer);
  }
  [pool release];
}


#pragma mark -
#pragma mark UITextField Delegate Methods

- (BOOL)textField:(UITextField *)textField
    shouldChangeCharactersInRange:(NSRange)range
    replacementString:(NSString *)string {
  if (textField == self.accountKey) {
    NSMutableString *key
      = [NSMutableString stringWithString:self.accountKey.text];
    [key replaceCharactersInRange:range withString:string];
    self.doneButtonItem.enabled = [key length] > 0;
  }
  return YES;
}

- (void)textFieldDidBeginEditing:(UITextField *)textField {
  self.activeTextField = textField;
}

- (void)textFieldDidEndEditing:(UITextField *)textField {
  self.activeTextField = nil;
}


#pragma mark -
#pragma mark DecoderDelegate

- (void)decoder:(Decoder *)decoder
 didDecodeImage:(UIImage *)image
    usingSubset:(UIImage *)subset
     withResult:(TwoDDecoderResult *)twoDResult {
  if (self.handleCapture) {
    self.handleCapture = NO;
    NSString *urlString = twoDResult.text;
    NSURL *url = [NSURL URLWithString:urlString];
    OTPAuthURL *authURL = [OTPAuthURL authURLWithURL:url
                                              secret:nil];
    [self.avSession stopRunning];
    if (authURL) {
      [self.delegate authURLEntryController:self didCreateAuthURL:authURL];
      [self dismissModalViewControllerAnimated:NO];
    } else {
      NSString *title = GTMLocalizedString(@"Invalid Barcode",
                                           @"Alert title describing a bad barcode");
      NSString *message = [NSString stringWithFormat:
                           GTMLocalizedString(@"The barcode '%@' is not a valid "
                                              @"authentication token barcode.",
                                              @"Alert describing invalid barcode type."),
                 urlString];
      NSString *button = GTMLocalizedString(@"Try Again",
                                            @"Button title to try again");
      UIAlertView *alert = [[[UIAlertView alloc] initWithTitle:title
                                                       message:message
                                                      delegate:self
                                             cancelButtonTitle:button
                                             otherButtonTitles:nil]
                            autorelease];
      [alert show];
    }
  }
}

- (void)decoder:(Decoder *)decoder failedToDecodeImage:(UIImage *)image
    usingSubset:(UIImage *)subset
         reason:(NSString *)reason {
}

#pragma mark -
#pragma mark UIAlertViewDelegate

- (void)alertView:(UIAlertView *)alertView
    didDismissWithButtonIndex:(NSInteger)buttonIndex {
  self.handleCapture = YES;
  [self.avSession startRunning];
}

@end
