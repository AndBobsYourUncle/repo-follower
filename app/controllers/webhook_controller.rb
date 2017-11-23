# frozen_string_literal: true

class WebhookController < ApplicationController
  def handle_webhook
    render :webhook
  end
end
