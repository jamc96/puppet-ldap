require 'spec_helper'
require 'puppet/type/authconfig'

RSpec.describe 'the authconfig type' do
  it 'loads' do
    expect(Puppet::Type.type(:authconfig)).not_to be_nil
  end
end
