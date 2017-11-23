# frozen_string_literal: true

require 'net/http'

class WebhookController < ApplicationController
  MAIN_REPO = 'AndBobsYourUncle/repo-follower'
  CHILD_REPO = 'AndBobsYourUncle/repo-follower-child'
  APP_ID = 6956
  INSTALLATION_ID = 69_303

  def handle_webhook
    request.body.rewind
    payload_body = request.body.read

    if payload_authorized?(payload_body)
      client = Octokit::Client.new(access_token: access_token)

      sha_latest_commit_child = client.ref(CHILD_REPO, 'heads/master').object.sha
      client.create_ref CHILD_REPO, 'heads/follower-changes', sha_latest_commit_child rescue Octokit::UnprocessableEntity

      sha_latest_commit = client.ref(MAIN_REPO, 'heads/master').object.sha
      last_main_commit = client.commit MAIN_REPO, sha_latest_commit

      new_tree_object = last_main_commit[:files].map do |file|
        blob = client.blob MAIN_REPO, file[:sha]

        blob_sha = client.create_blob CHILD_REPO, blob[:content], 'base64'

        {
          path: file[:filename],
          mode: '100644',
          type: 'blob',
          sha: blob_sha
        }
      end

      sha_base_tree = client.commit(CHILD_REPO, sha_latest_commit_child).commit.tree.sha
      sha_new_tree = client.create_tree(CHILD_REPO, new_tree_object, base_tree: sha_base_tree).sha

      commit_message = 'Merged from follower repo.'
      sha_new_commit = client.create_commit(CHILD_REPO, commit_message, sha_new_tree, sha_latest_commit_child).sha

      client.update_ref CHILD_REPO, 'heads/follower-changes', sha_new_commit

      pr = client.create_pull_request(
        CHILD_REPO, 'master', 'follower-changes',
        'Update from master repo', 'This is an automatic update from the master repo.'
      )

      client.merge_pull_request CHILD_REPO, pr[:number], 'App successfully updated from master repr.'

      render :webhook
    else
      render json: {
        error: 'Access denied',
        status: :unauthorized
      }
    end
  end

  private

  def github_private_key
    if Rails.env.development?
      File.read 'config/github_keys/repo-follower.pem'
    else
      Rails.application.secrets.github_private_pem
    end
    OpenSSL::PKey::RSA.new(private_pem)
  end

  def github_jwt
    payload = {
      iat: Time.now.to_i,
      exp: Time.now.to_i + (10 * 60),
      iss: APP_ID
    }

    JWT.encode payload, github_private_key, 'RS256'
  end

  def access_token
    uri = URI.parse "https://api.github.com/installations/#{INSTALLATION_ID}/access_tokens"
    http = Net::HTTP.new uri.host, uri.port
    http.use_ssl = true

    request = Net::HTTP::Post.new uri.request_uri
    request['Authorization'] = "Bearer #{github_jwt}"
    request['Accept'] = 'application/vnd.github.machine-man-preview+json'

    response = http.request request

    JSON.parse(response.body)['token']
  end

  def payload_authorized?(payload_body)
    signature = 'sha1=' + OpenSSL::HMAC.hexdigest(OpenSSL::Digest.new('sha1'), Rails.application.secrets.webhook_secret, payload_body)

    puts signature if Rails.env.development? # rubocop:disable Rails/Output

    Rack::Utils.secure_compare(signature, request.headers['HTTP_X_HUB_SIGNATURE'].to_s)
  end
end
