require 'fastlane/action'
require 'fileutils'
require_relative '../helper/match_keystore_helper'

module Fastlane
  module Actions
    module SharedValues
      MATCH_KEYSTORE_PATH = :MATCH_KEYSTORE_PATH
      MATCH_KEYSTORE_PASSWORD = :MATCH_KEYSTORE_PASSWORD
      MATCH_KEYSTORE_ALIAS_NAME = :MATCH_KEYSTORE_ALIAS_NAME
      MATCH_KEYSTORE_ALIAS_PASSWORD = :MATCH_KEYSTORE_ALIAS_PASSWORD
    end

    class MatchKeystoreAction < Action

      def self.load_properties(properties_filename)
        properties = {}
        File.open(properties_filename, 'r') do |properties_file|
          properties_file.read.each_line do |line|
            line.strip!
            if (line[0] != ?# and line[0] != ?=)
              i = line.index('=')
              if (i)
                properties[line[0..i - 1].strip] = line[i + 1..-1].strip
              else
                properties[line] = ''
              end
            end
          end      
        end
        properties
      end

      def self.get_android_home
        puts `rm -f android_home.txt`
        puts `echo $ANDROID_HOME > android_home.txt`
        data = File.read("android_home.txt")
        android_home = data.strip
        puts `rm -f android_home.txt`
        android_home
      end

      def self.get_build_tools
        android_home = self.get_android_home()
        build_tools_root = android_home + '/build-tools'

        sub_dirs = Dir.glob(File.join(build_tools_root, '*', ''))
        build_tools_last_version = ''
        for sub_dir in sub_dirs
          build_tools_last_version = sub_dir
        end

        build_tools_last_version
      end

      def self.gen_key(key_path, password)
        puts `rm -f #{key_path}`
        puts `echo "#{password}" | openssl dgst -sha512 | cut -c1-128 > #{key_path}`
      end

      def self.encrypt_file(clear_file, encrypt_file, key_path)
        puts `rm -f #{encrypt_file}`
        puts `openssl enc -aes-256-cbc -salt -in #{clear_file} -out #{encrypt_file} -pass file:#{key_path}`
      end

      def self.decrypt_file(encrypt_file, clear_file, key_path)
        puts `rm -f #{clear_file}`
        puts `openssl enc -d -aes-256-cbc -in #{encrypt_file} -out #{clear_file} -pass file:#{key_path}`
      end

      def self.sign_apk(apk_path, keystore_path, key_password, alias_name, alias_password, zip_align)

        build_tools_path = self.get_build_tools()

        # https://developer.android.com/studio/command-line/zipalign
        if zip_align == true
          apk_path_aligned = apk_path.gsub(".apk", "-aligned.apk")
          puts `rm -f #{apk_path_aligned}`
          puts `#{build_tools_path}zipalign 4 #{apk_path} #{apk_path_aligned}`
        else
          apk_path_aligned = apk_path
        end

        # https://developer.android.com/studio/command-line/apksigner
        apk_path_signed = apk_path.gsub(".apk", "-signed.apk")
        puts `rm -f #{apk_path_signed}`
        puts `#{build_tools_path}apksigner sign --ks #{keystore_path} --ks-key-alias #{alias_name} --ks-pass pass:#{alias_password} --key-pass pass:#{key_password} --v1-signing-enabled true --v2-signing-enabled true --out #{apk_path_signed} #{apk_path_aligned}`
    
        puts `#{build_tools_path}apksigner verify #{apk_path_signed}`
        puts `rm -f #{apk_path_aligned}`

        apk_path_signed
      end

      def self.resolve_apk_path(apk_path)
        if !apk_path.to_s.end_with?(".apk") 

          if !File.directory?(apk_path)
            apk_path = File.join(Dir.pwd, apk_path)
            puts apk_path
          end

          pattern = File.join(apk_path, '*.apk')
          files = Dir[pattern]

          for file in files
            if file.to_s.end_with?(".apk") && !file.to_s.end_with?("-signed.apk")  
              apk_path = file
              break
            end
          end

        end
        
        apk_path
      end

      def self.run(params)

        git_url = params[:git_url]
        package_name = params[:package_name]
        apk_path = params[:apk_path]
        override_keystore = params[:override_keystore]

        keystore_name = 'keystore.jks'
        properties_name = 'keystore.properties'
        properties_encrypt_name = 'keystore.properties.enc'

        # Check Android Home env:
        android_home = self.get_android_home()
        UI.message("Android SDK: #{android_home}")
        if android_home.to_s.strip.empty?
          raise "The environment variable ANDROID_HOME is not defined, or Android SDK is not installed!"
        end

        dir_name = ENV['HOME'] + '/.match_keystore'
        unless File.directory?(dir_name)
          UI.message("Creating '.match_keystore' working directory...")
          FileUtils.mkdir_p(dir_name)
        end

        key_path = dir_name + '/key.hex'
        if !File.file?(key_path)
          security_password = other_action.prompt(text: "Security password: ")
          self.gen_key(key_path, security_password)
        end

        repo_dir = dir_name + '/repo'
        unless File.directory?(repo_dir)
          UI.message("Creating repository directory...")
          FileUtils.mkdir_p(repo_dir)
        end

        gitDir = repo_dir + '/.git'
        unless File.directory?(gitDir)
          UI.message("Cloning remote Keystores repository...")
          puts `git clone #{git_url} #{repo_dir}`
        end

        keystoreAppDir = repo_dir + '/' + package_name
        unless File.directory?(keystoreAppDir)
          UI.message("Creating '#{package_name}' keystore directory...")
          FileUtils.mkdir_p(keystoreAppDir)
        end

        keystore_path = keystoreAppDir + '/' + keystore_name
        properties_path = keystoreAppDir + '/' + properties_name
        properties_encrypt_path = keystoreAppDir + '/' + properties_encrypt_name

         # Create keystore with command
        if !File.file?(keystore_path) || override_keystore

          if File.file?(keystore_path)
            FileUtils.remove_dir(keystore_path)
          end

          key_password = other_action.prompt(text: "Keystore Password: ")
          alias_name = other_action.prompt(text: "Keystore Alias name: ")
          alias_password = other_action.prompt(text: "Keystore Alias password: ")

          full_name = other_action.prompt(text: "Certificate First and Last Name: ")
          org_unit = other_action.prompt(text: "Certificate Organisation Unit: ")
          org = other_action.prompt(text: "Certificate Organisation: ")
          city_locality = other_action.prompt(text: "Certificate City or Locality: ")
          state_province = other_action.prompt(text: "Certificate State or Province: ")
          country = other_action.prompt(text: "Certificate Country Code (XX): ")

          # https://developer.android.com/studio/publish/app-signing
          UI.message("Generating Android Keystore...")
          keytool_parts = [
            "keytool -genkey -v",
            "-keystore #{keystore_path}",
            "-alias #{alias_name}",
            "-keyalg RSA -keysize 2048 -validity 10000",
            "-storepass #{alias_password} ",
            "-keypass #{key_password}",
            "-dname \"CN=#{full_name}, OU=#{org_unit}, O=#{org}, L=#{city_locality}, S=#{state_province}, C=#{country}\"",
          ]
          sh keytool_parts.join(" ")

          UI.message("Generating Keystore properties...")
         
          if File.file?(properties_path)
            FileUtils.remove_dir(properties_path)
          end
        
          store_file = git_url + '/' + package_name + '/' + keystore_name

          out_file = File.new(properties_path, "w")
          out_file.puts("keyFile=#{store_file}")
          out_file.puts("keyPassword=#{key_password}")
          out_file.puts("aliasName=#{alias_name}")
          out_file.puts("aliasPassword=#{alias_password}")
          out_file.close

          self.encrypt_file(properties_path, properties_encrypt_path, key_path)
          File.delete(properties_path)
          
          UI.message("Upload new Keystore to remote repository...")
          puts `cd #{repo_dir} && git add .`
          puts `cd #{repo_dir} && git commit -m "[ADD] Keystore for app '#{package_name}'."`
          puts `cd #{repo_dir} && git push`

        else
          UI.message "Keystore file already exists, continue..."

          self.decrypt_file(properties_encrypt_path, properties_path, key_path)

          properties = self.load_properties(properties_path)
          key_password = properties['keyPassword']
          alias_name = properties['aliasName']
          alias_password = properties['aliasPassword']

          File.delete(properties_path)

        end

        UI.message("Preparing Keystore data context...")
        Actions.lane_context[SharedValues::MATCH_KEYSTORE_PATH] = keystore_path
        Actions.lane_context[SharedValues::MATCH_KEYSTORE_PASSWORD] = key_password
        Actions.lane_context[SharedValues::MATCH_KEYSTORE_ALIAS_NAME] = alias_name
        Actions.lane_context[SharedValues::MATCH_KEYSTORE_ALIAS_PASSWORD] = alias_password

        output_signed_apk = ''
        apk_path = self.resolve_apk_path(apk_path)
        UI.message("APK to sign: " + apk_path)

        if File.file?(keystore_path)
          UI.message("Signing the APK...")
          output_signed_apk = self.sign_apk(
            apk_path, 
            keystore_path, 
            key_password, 
            alias_name, 
            alias_password, 
            true
          )
        end 

        output_signed_apk

      end

      def self.description
        "Easily sync your Android keystores across your team"
      end

      def self.authors
        ["Christopher NEY"]
      end

      def self.return_value
        "Prepare Keystore local path, alias name, and passwords for the specified App."
      end

      def self.output
        [
          ['MATCH_KEYSTORE_PATH', 'File path of the Keystore fot the App.'],
          ['MATCH_KEYSTORE_PASSWORD', 'Keystore password.'],
          ['MATCH_KEYSTORE_ALIAS_NAME', 'Keystore Alias Name.'],
          ['MATCH_KEYSTORE_ALIAS_PASSWORD', 'Keystore Alias Password.']
        ]
      end

      def self.details
        # Optional:
        "This way, your entire team can use the same account and have one code signing identity without any manual work or confusion."
      end

      def self.available_options
        [
           FastlaneCore::ConfigItem.new(key: :git_url,
                                   env_name: "MATCH_KEYSTORE_GIT_URL",
                                description: "The URL of the Git repository (Github, BitBucket...)",
                                   optional: false,
                                       type: String),
           FastlaneCore::ConfigItem.new(key: :package_name,
                                   env_name: "MATCH_KEYSTORE_PACKAGE_NAME",
                                description: "The package name of the App",
                                   optional: false,
                                       type: String),
          FastlaneCore::ConfigItem.new(key: :apk_path,
                                   env_name: "MATCH_KEYSTORE_APK_PATH",
                                description: "Path of the APK file to sign",
                                   optional: false,
                                       type: String),
           FastlaneCore::ConfigItem.new(key: :override_keystore,
                                   env_name: "MATCH_KEYSTORE_OVERRIDE",
                                description: "Override an existing Keystore (false by default)",
                                   optional: true,
                                       type: Boolean)
        ]
      end

      def self.is_supported?(platform)
        # Adjust this if your plugin only works for a particular platform (iOS vs. Android, for example)
        # See: https://docs.fastlane.tools/advanced/#control-configuration-by-lane-and-by-platform
        [:android].include?(platform)
      end
    end
  end
end
