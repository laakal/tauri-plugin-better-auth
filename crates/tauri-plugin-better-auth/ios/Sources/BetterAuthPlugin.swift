import AuthenticationServices
import SwiftRs
import Tauri
import UIKit
import WebKit

struct StartAuthArgs: Decodable {
  let url: String
  let scheme: String
}

/// `url` is the callback link; it is absent when the sheet was dismissed.
struct AuthResult: Encodable {
  let url: String?
}

/// Runs the sign-in page in an `ASWebAuthenticationSession`. The system hands
/// the `<scheme>://…` callback straight to this plugin, so the scheme does not
/// have to be registered in `Info.plist`.
///
/// All state is touched on the main queue only.
class BetterAuthPlugin: Plugin, ASWebAuthenticationPresentationContextProviding {
  private weak var webview: WKWebView?
  private var session: ASWebAuthenticationSession?
  /// The `startAuth` call waiting for the current session to end.
  private var pending: Invoke?
  /// Bumped whenever the current session is replaced or cancelled, so a late
  /// completion of an old session is ignored.
  private var generation = 0

  override func load(webview: WKWebView) {
    self.webview = webview
  }

  /// Presents the sign-in sheet. Resolves when the session ends: with the
  /// callback URL, or with no URL when the user dismissed it.
  @objc public func startAuth(_ invoke: Invoke) throws {
    let args = try invoke.parseArgs(StartAuthArgs.self)
    guard let url = URL(string: args.url) else {
      invoke.reject("The sign-in URL is not valid.")
      return
    }
    DispatchQueue.main.async {
      self.endCurrent()
      let id = self.generation
      let session = ASWebAuthenticationSession(url: url, callbackURLScheme: args.scheme) {
        [weak self] callbackURL, error in
        DispatchQueue.main.async {
          guard let self = self, self.generation == id else { return }
          if let callbackURL = callbackURL {
            self.settle { $0.resolve(AuthResult(url: callbackURL.absoluteString)) }
          } else if let error = error as? ASWebAuthenticationSessionError,
            error.code == .canceledLogin
          {
            self.settle { $0.resolve(AuthResult(url: nil)) }
          } else {
            let message = error?.localizedDescription ?? "The sign-in session failed."
            self.settle { $0.reject(message) }
          }
        }
      }
      session.presentationContextProvider = self
      self.session = session
      self.pending = invoke
      if !session.start() {
        self.settle { $0.reject("The sign-in sheet could not be presented.") }
      }
    }
  }

  /// Dismisses the sign-in sheet, if one is showing.
  @objc public func cancelAuth(_ invoke: Invoke) {
    DispatchQueue.main.async {
      self.endCurrent()
      invoke.resolve()
    }
  }

  /// Cancels the running session and reports it as dismissed.
  private func endCurrent() {
    generation += 1
    session?.cancel()
    settle { $0.resolve(AuthResult(url: nil)) }
  }

  /// Answers the waiting `startAuth` call, once.
  private func settle(_ answer: (Invoke) -> Void) {
    session = nil
    guard let invoke = pending else { return }
    pending = nil
    answer(invoke)
  }

  func presentationAnchor(for session: ASWebAuthenticationSession) -> ASPresentationAnchor {
    return webview?.window ?? manager.viewController?.view.window ?? ASPresentationAnchor()
  }
}

@_cdecl("init_plugin_better_auth")
func initPlugin() -> Plugin {
  return BetterAuthPlugin()
}
