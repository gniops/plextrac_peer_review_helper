from typing import Generator
from tqdm import tqdm
import ollama
import spacy
import torch
from text_generation import Client
from transformers import pipeline
import re
from collections import Counter
from typing import Callable
from bs4 import BeautifulSoup
from bs4.element import NavigableString, Tag


class LlamaModel:
    """ Supports remote Ollama server and local model loading """

    def __init__(
        self,
        ollama_remote_url: str = None,
        **kwargs,
    ) -> None:
        self.ollama_remote_url=ollama_remote_url
        self.client = ollama.Client(host=ollama_remote_url) if ollama_remote_url else ollama


    def get_llama_response(
        self,
        instruction: str,
        examples: str | list[str],
        temperature=0.1,
        model_name: str = "llama3:8b-instruct-fp16", # "llama3.2:3b-instruct-q3_K_L",
        **kwargs,
    ) -> list[str]:
        responses = []
        if isinstance(examples, str):
            examples = [examples]

        for example in examples:
            prompt = f"{instruction.strip()}\n\n{example.strip()}"
            try:
                response = self.client.generate(
                    model=model_name,  # Fixed: model_name should be a keyword argument
                    prompt=prompt,
                    options={"temperature": temperature, **kwargs}
                )
                responses.append(response["response"].strip())  # Ensure clean output
            except Exception as e:
                print(f"get_llama_response()->ollama.generate(): Error: {e}")
                return examples  # Fallback to original examples in case of error

        return responses


class GrammarlyModel:
    """Supports both TGI and local Hugging Face pipeline."""

    def __init__(
        self,
        tgi_remote_url: str = None,
        temperature: float = 0.7,
        model_name: str = "grammarly/coedit-xl",
        **kwargs,
    ) -> None:
        self.use_tgi = bool(tgi_remote_url)  # Determine mode based on presence of URL
        self.tgi_remote_url = tgi_remote_url

        if self.use_tgi:
            self.client = Client(tgi_remote_url)
        else:
            self.pipeline = pipeline(
                "text2text-generation",
                model=model_name,
                do_sample=True,
                device_map="auto",
                truncation=True,
                max_length=512,
                temperature=temperature,
                **kwargs,
            )  # type: ignore

    def __call__(
        self, text: str, instruction: str = "Rewrite to make this easier to understand:"
    ) -> str:
        prompt = f"{instruction} {text}"
       
        # If we are calling Grammarly via a connection to a Text Generation Interface Server
        if self.use_tgi:
            try:
                response = self.client.generate(prompt, max_new_tokens=256)
                return response.generated_text
            except Exception as e:
                print(f"__call__()->client.generate(): Error: {e}")
                return text  # Fallback to original text
        # We are calling the Grammarly model locally
        else:
            results = self.pipeline(prompt)[0]  # type: ignore
            return results["generated_text"]  # type: ignore

    def pipe(
        self,
        samples: list[str],
        batch_size=1,
        instruction: str = "Rewrite to make this easier to understand:",
    ) -> list[str]:
        output = []
        
        if self.use_tgi:
            for sent in tqdm(samples):
                prompt = f"{instruction} {sent}"
                try:
                    response = self.client.generate(prompt, max_new_tokens=256)
                    output.append(response.generated_text)
                except Exception as e:
                    print(f"pipe()->client.generate(): Error: {e}")
                    return samples

            return output
        else:
            with tqdm(samples) as prog_bar:
                for result in self.pipeline(
                    self._generator(samples, instruction=instruction), batch_size=batch_size
                ):  # nopep8 # type: ignore
                    output.append(result[0]["generated_text"])  # type: ignore
                    prog_bar.update(1)
                    prog_bar.refresh()
            return output

    def _generator(
        self,
        samples: list[str],
        instruction="Rewrite to make this easier to understand:",
    ) -> Generator[str, None, None]:
        for sent in samples:
            yield f"{instruction} {sent}"



class SpacyModel:
    def __init__(self) -> None:
        self.nlp = spacy.load("en_core_web_sm")

    def sent_tokenize(self, text: str) -> list[str]:
        doc = self.nlp(text)
        return [sent.text for sent in doc.sents]

    def word_tokenize(self, sentence: str) -> list[str]:
        doc = self.nlp(sentence)
        return [token.text for token in doc if token.is_alpha]

    def word_count(self, sentence: str) -> int:
        return len(self.word_tokenize(sentence))


class CopyEditor:
    """Main class for edits."""

    def __init__(self) -> None:
        self.spacy_model = SpacyModel()
        self.grammarly = None
        self.llama = None

    def clear_cache(self) -> None:
        if torch.cuda.is_available():
            torch.cuda.empty_cache()

    def load_grammarly_model(
        self,
        model_name: str = "grammarly/coedit-xl",
        temperature: float = 0.7,
        tgi_remote_url: str = None,
        **kwargs,
    ) -> None:
        """Load Grammarly model.

        Args:
            model_name (str, optional): Defaults to "grammarly/coedit-xl".
            temperature (float, optional): Creativity of the model,
                between 0-1. Defaults to 0.7.
        """
        if self.grammarly:
            del self.grammarly.pipeline  # type: ignore
            self.clear_cache()
        self.grammarly = GrammarlyModel(
            temperature=temperature, model_name=model_name, tgi_remote_url=tgi_remote_url, **kwargs
        )

    def sent_tokenize(self, text: str) -> list[str]:
        return self.spacy_model.sent_tokenize(text)

    def get_edits(
        self,
        text: str,
        use_grammarly: bool = True,
        use_llama: bool = True,
        grammarly_kwargs: dict | None = None,
        llama_kwargs: dict | None = None,
        prompts: dict | None = None,
    ) -> list[dict[str, str]]:

        if is_effectively_empty(text):
            return [text]

        sents=[text]

        default_grammarly_kwargs = {
            "model_name": "grammarly/coedit-xl",
            "temperature": 0.7,
        }

        grammarly_kwargs = default_grammarly_kwargs | (grammarly_kwargs or {})

        grammarly_batch_size = grammarly_kwargs.pop("batch_size", 8)

        default_llama_kwargs = {
            "model_name": "llama3:8b-instruct-fp16", #"llama3.2:3b-instruct-q3_K_L",
            "temperature": 0.3,
        }

        llama_kwargs = default_llama_kwargs | (llama_kwargs or {})

        default_prompts = {
            "grammarly": "Fix the grammar and return only the text and nothing more:",
            "llama": "Edit the grammar of the following text, returning only the edited text:",
        }

        prompts = default_prompts | (prompts or {})

        if use_llama and self.llama is not None:
            llama_edited = self.llama.get_llama_response(
                prompts[f"llama"], sents, **llama_kwargs
            )
        else:
            llama_edited=sents

        if use_grammarly:
            grammarly_edited = self.grammarly.pipe(
                llama_edited,
                batch_size=grammarly_batch_size,
                instruction=prompts[f"grammarly"],
            )
        else:
            grammarly_edited=llama_edited

        return grammarly_edited


def get_processed_edits(
    text: str,
    api,
    use_html_wrapping: bool = False,
    use_llama: bool = True,
    use_grammarly: bool = True,
    prompts: dict | None = None,
) -> str:
    """
    Returns the edited text using either plain or HTML-aware processing.
    """
    def run_edits(t: str) -> str:
        edits = api.copy_editor.get_edits(
            t,
            use_llama=use_llama,
            use_grammarly=use_grammarly,
            prompts=prompts or {},
        )
        return "".join(edits)

    if use_html_wrapping:
        return extractonlytext_sendtollm(text, run_edits)
    else:
        return run_edits(text)


def extractonlytext_sendtollm(
    html: str,
    edit_func: Callable,
    handle_inline_elements: bool = True,
) -> str:
    """
    Takes an HTML string and an edit function and returns a version of the
    HTML with edited paragraph text, keeping all other formatting the same.

    Args:
        html (str)
        edit_func (Callable): function that takes a string argument and returns
            a string. This would be the edit function of the LLM. Theinput to
            edit_func is NOT sentence-tokenized, so that needs to be handled by
            edit_func.
        handle_inline_elements (bool, optional): Automatically replaces span
            and anchor elements in modified text. This will fail if the
            span and anchor text sequences don't exist in the modified text (ie.
            if edit_func changes the text substantially.) If False, edit_func
            will have to handle replacing these elements, ie. you'll have to
            modify the LLM prompt.

    Returns:
        str
    """
    soup = BeautifulSoup(html, "html.parser")

    for paragraph in soup.find_all("p"):
        if handle_inline_elements:
            # Get text blocks from paragraph (usually one text block per
            # paragraph unless there's a non-inline element in it (ie. a code
            # tag))
            parsed = parse_p(paragraph)  # type: ignore

            for item in parsed:
                if isinstance(item, dict) and item["text"].strip():
                    # Get edited text for each text block
                    if is_effectively_empty(item["text"]):
                        new_text = item["text"]
                    else:
                        new_text = edit_func(item["text"])
                    item["new_content"] = add_inline_tags(new_text, item["inline_tags"])
            new_content = ""

            for item in parsed:
                # Reconstruct paragraph
                if isinstance(item, dict):
                    new_content += item.get("new_content", item["text"])

                else:
                    new_content += str(item)
        # Otherwise, pass inner HTML of paragraph to edit_func
        else:
            paragraph_html = paragraph.decode_contents()
            if is_effectively_empty(paragraph_html):
                new_content = paragraph_html
            else:
                new_content = edit_func(paragraph_html)

        paragraph.clear()  # type: ignore
        paragraph.append(BeautifulSoup(new_content, "html.parser"))  # type: ignore

    return str(soup)

def is_effectively_empty(text: str) -> bool:
    """Returns True if the text is only empty tags, whitespace, or invisible content."""
    if not text or not text.strip():
        return True

    # Parse and check if there's any real visible content
    soup = BeautifulSoup(text, "html.parser")
    visible = soup.get_text(strip=True)
    return len(visible) == 0


def parse_p(p: Tag):
    """
    Returns a list of element children/text from each paragraph element to be
    reconstructed later.
    """
    parsed_items = []
    current_text = ""
    current_inline_tags = []

    for i, child in enumerate(p.children):
        if child.name == "br":  # type: ignore
            continue
        if isinstance(child, Tag) and child.name in ("a", "span"):
            current_text += child.get_text()
            current_inline_tags.append(child)
        elif isinstance(child, NavigableString):
            current_text += str(child)
        else:
            if current_text:
                parsed_items.append(
                    {"text": current_text, "inline_tags": current_inline_tags}
                )
                current_text = ""
                current_inline_tags = []

            parsed_items.append(child)

    if current_text:
        parsed_items.append({"text": current_text, "inline_tags": current_inline_tags})
        current_text = ""
        current_inline_tags = []

    begin_children = []
    for child in p.children:
        if child.name == "br" or (  # type: ignore
            isinstance(child, NavigableString) and not child.get_text().strip()
        ):
            begin_children.append(child)
        else:
            break
    for item in reversed(begin_children):
        parsed_items.insert(0, item)

    end_children = []
    for child in reversed(list(p.children)):
        if child.name == "br" or (  # type: ignore
            isinstance(child, NavigableString) and not child.get_text().strip()
        ):
            end_children.append(child)

        else:
            break
    parsed_items.extend(reversed(end_children))
    return parsed_items


def replace_nth(text: str, target: str, replace: str, n: int) -> str:
    """Replace nth occurence of "target" in "text" with "replace" string."""
    try:
        where = [m.start() for m in re.finditer(re.escape(target), text)][n - 1]
    except IndexError:
        return text
    before = text[:where]
    after = text[where:]
    after = after.replace(target, replace, 1)
    new_text = before + after
    return new_text


def add_inline_tags(text: str, tag_list: list[Tag]) -> str:
    """Adds tags back to text."""
    match_counter = Counter()
    for tag in tag_list:
        tag_text = tag.get_text()
        match_counter[tag_text] += 1
        text = replace_nth(text, tag_text, str(tag), match_counter[tag_text])
    return text
