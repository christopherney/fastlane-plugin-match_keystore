describe Fastlane::Actions::MatchKeystoreAction do
  describe '#run' do
    it 'prints a message' do
      expect(Fastlane::UI).to receive(:message).with("The match_keystore plugin is working!")

      Fastlane::Actions::MatchKeystoreAction.run(nil)
    end
  end
end
