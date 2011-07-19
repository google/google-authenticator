//
//  OTPAuthAboutController.m
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

#import "OTPAuthAboutController.h"
#import "UIColor+MobileColors.h"
#import "GTMLocalizedString.h"

@interface OTPAuthAboutWebViewController : UIViewController
  <UIWebViewDelegate, UIAlertViewDelegate> {
 @private
  NSURL *url_;
  NSString *label_;
  UIActivityIndicatorView *spinner_;
}
- (id)initWithURL:(NSURL *)url accessibilityLabel:(NSString *)label;
@end

@implementation OTPAuthAboutController

- (id)init {
  return [super initWithNibName:@"OTPAuthAboutController" bundle:nil];
}

- (void)viewDidLoad {
  UITableView *view = (UITableView *)[self view];
  [view setAccessibilityLabel:@"LegalOptions"];
  [view setBackgroundColor:[UIColor googleBlueBackgroundColor]];
}

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

#pragma mark -
#pragma mark TableView Delegate

- (NSInteger)numberOfSectionsInTableView:(UITableView *)tableView {
  return 1;
}

- (NSInteger)tableView:(UITableView *)tableView
 numberOfRowsInSection:(NSInteger)section {
  return 3;
}

- (NSString *)tableView:(UITableView *)tableView
    titleForFooterInSection:(NSInteger)section {
  NSString *version
      = [[NSBundle mainBundle] objectForInfoDictionaryKey:@"CFBundleVersion"];
  version = [NSString stringWithFormat:@"Version: %@", version];
  return version;
}

- (UITableViewCell *)tableView:(UITableView *)tableView
         cellForRowAtIndexPath:(NSIndexPath *)indexPath {

  static NSString *CellIdentifier = @"AboutCell";

  UITableViewCell *cell
    = [tableView dequeueReusableCellWithIdentifier:CellIdentifier];
  if (!cell) {
    cell = [[[UITableViewCell alloc] initWithStyle:UITableViewCellStyleValue1
                                   reuseIdentifier:CellIdentifier] autorelease];
    [cell setAccessoryType:UITableViewCellAccessoryDisclosureIndicator];
  }

  NSString *text = nil;
  NSString *label = nil;
  switch([indexPath row]) {
    case 0:
      label = @"Terms of Service";
      text = GTMLocalizedString(@"Terms of Service",
                                @"Terms of Service Table Item Title");
      break;

    case 1:
      label = @"Privacy Policy";
      text = GTMLocalizedString(@"Privacy Policy",
                                @"Privacy Policy Table Item Title");
      break;

    case 2:
      label = @"Legal Notices";
      text = GTMLocalizedString(@"Legal Notices",
                                @"Legal Notices Table Item Title");
      break;

    default:
      label = @"Unknown Index";
      text = label;
      break;
  }
  [[cell textLabel] setText:text];
  [cell setIsAccessibilityElement:YES];
  [cell setAccessibilityLabel:label];
  return cell;
}

- (void)tableView:(UITableView *)tableView
    didSelectRowAtIndexPath:(NSIndexPath *)indexPath {
  NSURL *url = nil;
  NSString *label = nil;
  switch([indexPath row]) {
    case 0: {
      url = [NSURL URLWithString:@"http://m.google.com/tospage"];
      label = @"Terms of Service";
      break;
    }

    case 1:
      // Privacy appears to do the localization thing correctly. So no hacks
      // needed (contrast to case 0 above.
      url = [NSURL URLWithString:@"http://www.google.com/mobile/privacy.html"];
      label = @"Privacy Policy";
      break;

    case 2: {
        NSBundle *bundle = [NSBundle mainBundle];
        NSString *legalNotices = [bundle pathForResource:@"LegalNotices"
                                                  ofType:@"html"];
        url = [NSURL fileURLWithPath:legalNotices];
        label = @"Legal Notices";
      }
      break;

    default:
      break;
  }
  if (url) {
    OTPAuthAboutWebViewController *controller
        = [[[OTPAuthAboutWebViewController alloc] initWithURL:url
                                           accessibilityLabel:label]
           autorelease];
    [[self navigationController] pushViewController:controller animated:YES];
  }
}

@end

@implementation OTPAuthAboutWebViewController

- (id)initWithURL:(NSURL *)url accessibilityLabel:(NSString *)label {
  if ((self = [super initWithNibName:nil bundle:nil])) {
    url_ = [url retain];
    label_ = [label copy];
  }
  return self;
}

- (void)dealloc {
  [url_ release];
  [label_ release];
  [super dealloc];
}

- (void)loadView {
  UIWebView *webView
    = [[[UIWebView alloc] initWithFrame:CGRectZero] autorelease];
  [webView setScalesPageToFit:YES];
  [webView setDelegate:self];
  [webView setAccessibilityLabel:label_];
  NSURLRequest *request = [NSURLRequest requestWithURL:url_];
  [webView loadRequest:request];
  [self setView:webView];
}


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

#pragma mark -
#pragma mark UIWebViewDelegate

- (void)webViewDidStartLoad:(UIWebView *)webView {
  spinner_ = [[UIActivityIndicatorView alloc]
              initWithActivityIndicatorStyle:UIActivityIndicatorViewStyleGray];
  CGRect bounds = webView.bounds;
  CGPoint middle = CGPointMake(CGRectGetMidX(bounds), CGRectGetMidY(bounds));
  [spinner_ setCenter:middle];
  [webView addSubview:spinner_];
  [spinner_ startAnimating];
}

- (void)stopSpinner {
  [spinner_ stopAnimating];
  [spinner_ removeFromSuperview];
  [spinner_ release];
  spinner_ = nil;
}

- (void)webViewDidFinishLoad:(UIWebView *)webView {
  [self stopSpinner];
}

- (void)webView:(UIWebView *)webView didFailLoadWithError:(NSError *)error {
  [self stopSpinner];
  NSString *errString
    = GTMLocalizedString(@"Unable to load webpage.",
                         @"Notification that a web page cannot be loaded");
  UIAlertView *alert
    = [[[UIAlertView alloc] initWithTitle:errString
                                  message:[error localizedDescription]
                                 delegate:nil
                        cancelButtonTitle:GTMLocalizedString(@"OK",
                                                             @"OK button")
                        otherButtonTitles:nil] autorelease];
  [alert setDelegate:self];
  [alert show];
}


#pragma mark -
#pragma mark UIAlertViewDelegate

- (void)alertView:(UIAlertView *)alertView
  clickedButtonAtIndex:(NSInteger)buttonIndex {
  [[self navigationController] popViewControllerAnimated:YES];
}

@end
