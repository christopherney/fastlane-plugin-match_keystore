# match_keystore plugin

[![fastlane Plugin Badge](https://rawcdn.githack.com/fastlane/fastlane/master/fastlane/assets/plugin-badge.svg)](https://rubygems.org/gems/fastlane-plugin-match_keystore)

## Machine requirements

* OpenSSL 1.1.1 min OR LibreSSL 2.9 min installed
* Git installed
* Android SDK & Build-tools installed
* ANDROID_HOME environment variable defined

## Getting Started

This project is a [_fastlane_](https://github.com/fastlane/fastlane) plugin. To get started with `fastlane-plugin-match_keystore`, add it to your project by running:

```bash
fastlane add_plugin match_keystore
```

## About match_keystore

Easily sync your Android keystores across your team.

This plugin was design based on the 'match' plugin and code signing concept: https://codesigning.guide/

With **match_keystore** you can store all your Android Keystores in secured private repository and share it to your team and your CI system.

The keystore properties are encrypted with AES in order to secure sensitive data in the Git repository itself.

## How to use

```ruby
  lane :release_and_sign do |options|
    gradle(task: "clean")
    gradle(task: 'assemble', build_type: 'Release')

    signed_apk_path = match_keystore(
      git_url: "https://github.com/<GITHUB_USERNAME>/keystores.git", # Please use a private Git repository !
      package_name: "com.your.package.name",
      apk_path: "/app/build/outputs/apk/app-release.apk" # Or path without APK: /app/build/outputs/apk/
      # Optional:
      match_secret: "A-very-str0ng-password!", # The secret use to encrypt/decrypt Keystore passwords on Git repo (for CI)
      existing_keystore: "assets/existing-keystore.jks", # Optional, if needed to import an existing keystore
      override_keystore: true, # Optional, override an existing Keystore on Git repo
      keystore_data: "assets/keystore.json" # Optional, all data required to create a new Keystore (use to bypass prompt)
    )

    # Return the path of signed APK (useful for other lanes such as `publish_to_firebase`, `upload_to_play_store`)
    puts signed_apk_path
  end
```

You can build aab files as well by providing an `aab_path` instead of an `apk_path`.

## Example

Check out the [example `Fastfile`](fastlane/Fastfile) to see how to use this plugin. Try it by cloning the repo, running `fastlane install_plugins` and `bundle exec fastlane test`.

**Note to author:** Please set up a sample project to make it easy for users to explore what your plugin does. Provide everything that is necessary to try out the plugin in this project (including a sample Xcode/Android project if necessary)

## Run tests for this plugin

To run both the tests, and code style validation, run

```
rake
```

To automatically fix many of the styling issues, use
```
rubocop -a
```

## Issues and Feedback

For any other issues and feedback about this plugin, please submit it to this repository.

## Troubleshooting

If you have trouble using plugins, check out the [Plugins Troubleshooting](https://docs.fastlane.tools/plugins/plugins-troubleshooting/) guide.

## Using _fastlane_ Plugins

For more information about how the `fastlane` plugin system works, check out the [Plugins documentation](https://docs.fastlane.tools/plugins/create-plugin/).

## About _fastlane_

_fastlane_ is the easiest way to automate beta deployments and releases for your iOS and Android apps. To learn more, check out [fastlane.tools](https://fastlane.tools).
