module Jekyll
  class PasswordProtectGenerator < Generator
    def generate(site)
      site.posts.docs.each do |post|
        if post.data['layout'] == 'protected'
          post.data['protected'] = true
          post.data['password'] = 'yrr3j'
        end
      end
    end
  end
end

